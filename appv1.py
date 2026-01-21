import os
import json
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st

ORANGE = "#ff7a00"

# ---- Optional imports from your pipelines (keep app runnable even if import fails) ----
PIPE1_OK = True
PIPE2_OK = True

try:
    from pipeline1 import train_and_save_best_model as train_and_save_best_model_p1
except Exception as e:
    PIPE1_OK = False
    _PIPE1_ERR = e

try:
    from pipeline2 import load_model_payload, run_prediction_cycle
except Exception as e:
    PIPE2_OK = False
    _PIPE2_ERR = e


# --------------------------- Helpers ---------------------------

def _ensure_severity_from_rule_level(df: pd.DataFrame) -> pd.DataFrame:
    """
    If 'severity' is missing but 'rule.level' exists, derive it:
    0-3 -> low, 4-7 -> medium, 8-11 -> high, 12+ -> critical
    """
    if "severity" in df.columns:
        return df
    if "rule.level" not in df.columns:
        return df

    s = pd.to_numeric(df["rule.level"], errors="coerce")
    sev = pd.Series(index=df.index, dtype="object")
    sev[s.between(0, 3, inclusive="both")] = "low"
    sev[s.between(4, 7, inclusive="both")] = "medium"
    sev[s.between(8, 11, inclusive="both")] = "high"
    sev[s >= 12] = "critical"
    out = df.copy()
    out["severity"] = sev
    return out


def _save_df_to_tmp_csv(df: pd.DataFrame) -> str:
    tmp_dir = Path("tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(tmp_path, index=False)
    return str(tmp_path)


def _load_metrics_json(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _get_feature_cols(model_payload: dict):
    # Support multiple key names depending on how pipeline1/pipeline2 saved it.
    for k in ["feature_cols", "feature_columns", "features", "columns"]:
        if k in model_payload and isinstance(model_payload[k], (list, tuple)) and len(model_payload[k]) > 0:
            return list(model_payload[k])
    raise KeyError("Model payload does not contain feature columns (expected feature_cols/feature_columns).")


def _predict_on_df(df: pd.DataFrame, model_payload: dict) -> pd.DataFrame:
    """
    Predict severity on a dataframe using the saved feature columns from training.
    - model_payload expects: {"model", ("feature_cols" or "feature_columns"), optional "label_encoder"}
    - ensures all training columns exist, then reindexes in the same order
    - returns df with predicted_severity column
    """
    if "model" not in model_payload:
        raise KeyError("Model payload missing 'model'.")
    model = model_payload["model"]
    feature_cols = _get_feature_cols(model_payload)

    X = df.copy()
    # ensure all expected columns exist
    for col in feature_cols:
        if col not in X.columns:
            X[col] = np.nan

    X = X.reindex(columns=feature_cols)

    y_pred = model.predict(X)

    # If a LabelEncoder exists, map back to string labels
    le = model_payload.get("label_encoder", None)
    if le is not None:
        try:
            y_pred = le.inverse_transform(y_pred)
        except Exception:
            pass

    out = df.copy()
    out["predicted_severity"] = pd.Series(y_pred, index=out.index).astype(str)
    return out


def _append_predictions_to_jsonl(df_pred: pd.DataFrame, log_path: str):
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # keep only JSON-serializable columns by converting timestamps/np types
    def _to_py(x):
        if pd.isna(x):
            return None
        if isinstance(x, (np.integer, np.floating)):
            return x.item()
        if isinstance(x, (pd.Timestamp, datetime)):
            return x.isoformat()
        return x

    with p.open("a", encoding="utf-8") as f:
        for _, row in df_pred.iterrows():
            obj = {k: _to_py(v) for k, v in row.to_dict().items()}
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _read_last_jsonl(log_path: str, n: int = 200) -> pd.DataFrame:
    p = Path(log_path)
    if not p.exists():
        return pd.DataFrame()
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    lines = [ln for ln in lines if ln.strip()]
    tail = lines[-n:]
    rows = []
    for ln in tail:
        try:
            rows.append(json.loads(ln))
        except Exception:
            continue
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def _plot_bar_counts(series: pd.Series, title: str):
    import matplotlib.pyplot as plt
    vc = series.value_counts(dropna=False)
    fig, ax = plt.subplots()
    vc.plot(kind="bar", ax=ax)
    ax.set_title(title)
    ax.set_xlabel(series.name or "")
    ax.set_ylabel("count")
    st.pyplot(fig)



def _plot_top_n(series: pd.Series, title: str, n: int = 15):
    import matplotlib.pyplot as plt
    vc = series.astype(str).fillna("").replace({"<NA>": ""})
    vc = vc[vc != ""].value_counts().head(n)
    if vc.empty:
        st.caption("Aucune donnée disponible.")
        return
    fig, ax = plt.subplots()
    vc.sort_values().plot(kind="barh", ax=ax)
    ax.set_title(title)
    ax.set_xlabel("count")
    ax.set_ylabel("")
    st.pyplot(fig)


def _plot_time_series_counts(df: pd.DataFrame, ts_col: str, title: str, freq: str = "H"):
    import matplotlib.pyplot as plt
    tmp = df.copy()
    tmp[ts_col] = pd.to_datetime(tmp[ts_col], errors="coerce", utc=True)
    tmp = tmp[tmp[ts_col].notna()].copy()
    if tmp.empty:
        st.caption("Aucune date/heure valide pour cette sélection.")
        return
    tmp["bucket"] = tmp[ts_col].dt.floor(freq)
    ts = tmp.groupby("bucket").size()
    fig, ax = plt.subplots()
    ts.plot(ax=ax)
    ax.set_title(title)
    ax.set_xlabel("time")
    ax.set_ylabel("count")
    st.pyplot(fig)


def _plot_numeric_corr_heatmap(df: pd.DataFrame, title: str):
    import matplotlib.pyplot as plt
    num = df.select_dtypes(include=["number"]).copy()
    if num.shape[1] < 2:
        st.caption("Pas assez de colonnes numériques pour une corrélation.")
        return
    corr = num.corr(numeric_only=True)
    fig, ax = plt.subplots()
    im = ax.imshow(corr.values, aspect="auto")
    ax.set_title(title)
    ax.set_xticks(range(len(corr.columns)))
    ax.set_xticklabels(corr.columns, rotation=90)
    ax.set_yticks(range(len(corr.columns)))
    ax.set_yticklabels(corr.columns)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    st.pyplot(fig)


def _plot_confusion_matrix(y_true: pd.Series, y_pred: pd.Series):
    from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix
    import matplotlib.pyplot as plt

    labels = sorted(
        list(set(y_true.dropna().astype(str).unique()).union(set(y_pred.dropna().astype(str).unique())))
    )
    cm = confusion_matrix(y_true.astype(str), y_pred.astype(str), labels=labels)
    fig, ax = plt.subplots()
    disp = ConfusionMatrixDisplay(cm, display_labels=labels)
    disp.plot(ax=ax, values_format="d", colorbar=False)
    ax.set_title("Confusion matrix")
    st.pyplot(fig)


# --------------------------- UI ---------------------------

st.set_page_config(page_title="Wazuh ML – Training & Prediction", layout="wide")
st.title("Wazuh ML – Training & Prediction app")

with st.sidebar:
    st.header("Config Indexer")
    default_base_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
    default_user = os.getenv("WAZUH_INDEXER_USER", "admin")
    default_pass = os.getenv("WAZUH_INDEXER_PASS", "admin")

    base_url = st.text_input("Indexer base_url", value=default_base_url)
    username = st.text_input("Username", value=default_user)
    password = st.text_input("Password", value=default_pass, type="password")
    source_index = st.text_input("Source index", value=os.getenv("WAZUH_SOURCE_INDEX", "wazuh-alerts-*"))

    st.divider()
    st.caption("Pipelines status")
    if PIPE1_OK:
        st.success("pipeline1: OK")
    else:
        st.error(f"pipeline1 import error: {_PIPE1_ERR}")

    if PIPE2_OK:
        st.success("pipeline2: OK")
    else:
        st.error(f"pipeline2 import error: {_PIPE2_ERR}")


tab_data, tab_train, tab_predict = st.tabs(["📄 Dataset (EDA)", "🧠 Training", "🔮 Prediction (new dataset)"])

# --------------------------- Dataset (EDA) ---------------------------
with tab_data:
    st.subheader("Charger un dataset CSV pour EDA et filtrage avant training")

    up = st.file_uploader("Upload CSV (dataset pour EDA & training)", type=["csv"], key="uploader_train")
    if up is None:
        st.info("Upload un fichier CSV pour commencer (EDA + training).")
        st.stop()

    df = pd.read_csv(up, low_memory=False)
    df = _ensure_severity_from_rule_level(df)

    # Basic KPIs
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Lignes", f"{len(df):,}".replace(",", " "))
    c2.metric("Colonnes", f"{df.shape[1]:,}".replace(",", " "))
    c3.metric("Duplicats", f"{df.duplicated().sum():,}".replace(",", " "))
    c4.metric("Missing cells", f"{int(df.isna().sum().sum()):,}".replace(",", " "))

    st.write("Aperçu")
    st.dataframe(df.head(50), use_container_width=True)

    with st.expander("Colonnes"):
        st.code(", ".join(df.columns))

    # EDA: Missing values top
    st.markdown("### EDA")
    left, right = st.columns(2)
    with left:
        miss = df.isna().mean().sort_values(ascending=False)
        miss = miss[miss > 0].head(25).reset_index()
        miss.columns = ["column", "missing_ratio"]
        if len(miss):
            st.caption("Top colonnes avec valeurs manquantes")
            st.dataframe(miss, use_container_width=True, hide_index=True)
        else:
            st.caption("Aucune valeur manquante détectée.")

    with right:
        if "severity" in df.columns:
            _plot_bar_counts(df["severity"].astype(str), "Distribution de severity (dataset importé)")
        elif "rule.level" in df.columns:
            _plot_bar_counts(pd.to_numeric(df["rule.level"], errors="coerce").dropna(), "Distribution rule.level")

    # Filtering
    st.divider()
    st.subheader("Filtrage simple (pour training)")

    col1, col2, col3 = st.columns(3)
    with col1:
        if "severity" in df.columns:
            sev_vals = sorted([x for x in df["severity"].dropna().astype(str).unique().tolist()])
            sev_filter = st.multiselect("severity", sev_vals, default=sev_vals)
        else:
            sev_filter = None

    with col2:
        if "rule.id" in df.columns:
            rule_vals = df["rule.id"].dropna().astype(str).unique().tolist()
            rule_filter = st.multiselect("rule.id (optionnel)", sorted(rule_vals)[:200], default=[])
        else:
            rule_filter = None

    with col3:
        text_search = st.text_input("Recherche texte (optionnel)", value="", key="search_train")

    df_f = df.copy()
    if sev_filter is not None:
        df_f = df_f[df_f["severity"].astype(str).isin(sev_filter)]

    if rule_filter is not None and len(rule_filter) > 0:
        df_f = df_f[df_f["rule.id"].astype(str).isin(rule_filter)]

    if text_search.strip():
        candidates = [c for c in ["full_log", "data.win.eventdata.commandLine", "rule.description", "message"] if c in df_f.columns]
        if candidates:
            mask = False
            for c in candidates:
                mask = mask | df_f[c].astype(str).str.contains(text_search, case=False, na=False)
            df_f = df_f[mask]
        else:
            st.warning("Aucune colonne texte connue trouvée pour la recherche (full_log/message/...).")


    st.markdown("### EDA avancée (sur dataset filtré)")

    g1, g2 = st.columns(2)
    with g1:
        if "rule.id" in df_f.columns:
            _plot_top_n(df_f["rule.id"], "Top rule.id (filtré)", n=15)
        if "agent.name" in df_f.columns:
            _plot_top_n(df_f["agent.name"], "Top agent.name (filtré)", n=15)

    with g2:
        if "rule.description" in df_f.columns:
            _plot_top_n(df_f["rule.description"], "Top rule.description (filtré)", n=15)
        if "rule.level" in df_f.columns:
            import matplotlib.pyplot as plt
            lv = pd.to_numeric(df_f["rule.level"], errors="coerce").dropna()
            if len(lv):
                fig, ax = plt.subplots()
                ax.hist(lv, bins=20)
                ax.set_title("Histogramme rule.level (filtré)")
                ax.set_xlabel("rule.level")
                ax.set_ylabel("count")
                st.pyplot(fig)

    # Série temporelle si colonne timestamp existe
    ts_candidates = [c for c in ["@timestamp", "timestamp", "event.created", "time"] if c in df_f.columns]
    if ts_candidates:
        _plot_time_series_counts(df_f, ts_candidates[0], f"Volume d'événements dans le temps ({ts_candidates[0]})", freq="H")

    # Corrélation numérique
    with st.expander("Corrélation (numérique)"):
        _plot_numeric_corr_heatmap(df_f, "Heatmap corrélation (colonnes numériques)")

    st.success(f"Dataset filtré (training): {len(df_f)} lignes")
    st.dataframe(df_f.head(50), use_container_width=True)

    st.session_state["df_filtered"] = df_f  # share across tabs

    st.download_button(
        "Télécharger le dataset filtré (CSV)",
        data=df_f.to_csv(index=False).encode("utf-8"),
        file_name="dataset_filtre_training.csv",
        mime="text/csv",
    )


# --------------------------- Training ---------------------------
with tab_train:
    st.subheader("Training du modèle de sévérité")

    if not PIPE1_OK:
        st.error("pipeline1 n'est pas importable. Corrige pipeline1.py puis relance.")
        st.stop()

    df_f = st.session_state.get("df_filtered")
    if df_f is None or len(df_f) == 0:
        st.warning("Pas de dataset filtré. Va dans l’onglet Dataset (EDA).")
        st.stop()

    c1, c2 = st.columns(2)
    with c1:
        model_path = st.text_input("output_model_path", value="models/best_severity_model.joblib")
    with c2:
        metrics_path = st.text_input("output_metrics_path", value="models/severity_metrics.json")

    st.caption("Le training lit un CSV; on exporte ton dataset filtré en CSV temporaire pour l'entraîner.")
    if st.button("Lancer le training et sauvegarder le meilleur modèle", type="primary"):
        try:
            tmp_csv = _save_df_to_tmp_csv(df_f)
            out_model, metrics = train_and_save_best_model_p1(
                dataset_path=tmp_csv,
                output_model_path=model_path,
                output_metrics_path=metrics_path,
            )
            st.success(f"✅ Modèle sauvegardé: {out_model}")
            st.json(metrics)

            st.session_state["last_model_path"] = out_model
            st.session_state["last_metrics_path"] = metrics_path

            if Path(out_model).exists():
                st.download_button(
                    "Télécharger le modèle (.joblib)",
                    data=Path(out_model).read_bytes(),
                    file_name=Path(out_model).name,
                )
            if Path(metrics_path).exists():
                st.download_button(
                    "Télécharger les métriques (.json)",
                    data=Path(metrics_path).read_bytes(),
                    file_name=Path(metrics_path).name,
                )
        except Exception as e:
            st.exception(e)


# --------------------------- Prediction (NEW dataset) ---------------------------
with tab_predict:
    st.subheader("Prédire la sévérité sur un NOUVEAU dataset importé (modèle déjà entraîné)")

    if not PIPE2_OK:
        st.error("pipeline2 n'est pas importable. Corrige pipeline2.py puis relance.")
        st.stop()

    default_model = st.session_state.get("last_model_path", "models/best_severity_model.joblib")
    default_metrics = st.session_state.get("last_metrics_path", "models/severity_metrics.json")

    c1, c2 = st.columns(2)
    with c1:
        model_path = st.text_input("Chemin du modèle (.joblib)", value=default_model, key="model_path_pred")
    with c2:
        metrics_path = st.text_input("Chemin des métriques (.json) (optionnel)", value=default_metrics, key="metrics_path_pred")

    st.markdown("#### 1) Importer un dataset pour prédiction")
    up_pred = st.file_uploader("Upload CSV (dataset de prédiction)", type=["csv"], key="uploader_pred")
    if up_pred is None:
        st.info("Upload un fichier CSV ici pour faire la prédiction avec le modèle déjà entraîné.")
        st.stop()

    df_new = pd.read_csv(up_pred, low_memory=False)
    df_new = _ensure_severity_from_rule_level(df_new)  # keeps ground-truth if already there

    st.write("Aperçu dataset de prédiction")
    st.dataframe(df_new.head(30), use_container_width=True)

    st.markdown("#### 2) Paramètres de prédiction")
    max_rows = int(min(5000, len(df_new)))
    with st.form("predict_form"):
        n_rows = st.slider(
            "Nombre de lignes à prédire",
            min_value=1,
            max_value=max_rows if max_rows > 0 else 1,
            value=min(500, max_rows) if max_rows > 0 else 1,
        )
        log_path = st.text_input("Chemin du log local (jsonl)", value="logs/predictions_local.jsonl")
        submit = st.form_submit_button("Lancer la prédiction (batch)", type="primary")

    if submit:
        try:
            if not Path(model_path).exists():
                st.error("Modèle introuvable. Corrige le chemin du modèle (.joblib).")
                st.stop()

            payload = load_model_payload(model_path)
            df_pred = _predict_on_df(df_new.head(n_rows), payload)

            # Save logs (append)
            _append_predictions_to_jsonl(df_pred, log_path)

            st.success(f"✅ Prédictions terminées sur {len(df_pred)} lignes")
            st.session_state["df_predicted"] = df_pred
            st.session_state["last_pred_log_path"] = log_path

            st.markdown("### Logs (dataset + colonne predicted_severity)")

            # Afficher uniquement predicted_severity (et la mettre en dernière colonne)
            logs_df = df_pred.copy()
            if "severity" in logs_df.columns:
                logs_df = logs_df.drop(columns=["severity"])
            if "predicted_severity" in logs_df.columns:
                cols = [c for c in logs_df.columns if c != "predicted_severity"] + ["predicted_severity"]
                logs_df = logs_df[cols]

            # Styling: predicted_severity en orange + bold (appliqué sur un extrait pour performance)
            # Limit rows BEFORE styling (Styler has no .head)
            logs_view = logs_df.head(200)

            styled_view = logs_view.style.set_properties(
                subset=["predicted_severity"],
                **{"color": ORANGE, "font-weight": "700"}
            )

            st.dataframe(styled_view, use_container_width=True, hide_index=True)

            st.download_button(
                "Télécharger les logs prédits (CSV)",
                data=logs_df.to_csv(index=False).encode("utf-8"),
                file_name="logs_predicted.csv",
                mime="text/csv",
            )

            # --- Metrics single object (optional) ---
            metrics = _load_metrics_json(metrics_path)
            if metrics:
                st.markdown("### Métriques du modèle (metrics.json)")
                mcols = st.columns(4)
                if "accuracy" in metrics:
                    mcols[0].metric("Accuracy", round(float(metrics.get("accuracy", 0)), 3))
                if "f1_macro" in metrics:
                    mcols[1].metric("F1 macro", round(float(metrics.get("f1_macro", 0)), 3))
                if "precision_macro" in metrics:
                    mcols[2].metric("Precision macro", round(float(metrics.get("precision_macro", 0)), 3))
                if "recall_macro" in metrics:
                    mcols[3].metric("Recall macro", round(float(metrics.get("recall_macro", 0)), 3))
            else:
                st.caption("metrics.json introuvable ou vide (ce n'est pas bloquant).")

            st.markdown("### Visualisations sur la prédiction")
            _plot_bar_counts(df_pred["predicted_severity"], "Distribution des severities prédites")

            # time evolution if timestamp exists
            for ts_col in ["@timestamp", "timestamp", "event.created", "time"]:
                if ts_col in df_pred.columns:
                    ts = pd.to_datetime(df_pred[ts_col], errors="coerce", utc=True)
                    if ts.notna().any():
                        tmp = df_pred.copy()
                        tmp["_ts_hour"] = ts.dt.floor("H")
                        grp = tmp.groupby("_ts_hour")["predicted_severity"].value_counts().unstack(fill_value=0)

                        import matplotlib.pyplot as plt
                        fig, ax = plt.subplots()
                        grp.plot(ax=ax)
                        ax.set_title(f"Évolution des severities prédites (par heure) – {ts_col}")
                        ax.set_xlabel("Heure")
                        ax.set_ylabel("count")
                        st.pyplot(fig)
                        break


            # Advanced graphs
            st.markdown("#### Graphes avancés")

            # 1) Stacked timeline (severity predicted over time)
            _stacked_done = False
            for ts_col in ["@timestamp", "timestamp", "event.created", "time"]:
                if ts_col in df_pred.columns:
                    ts = pd.to_datetime(df_pred[ts_col], errors="coerce", utc=True)
                    if ts.notna().any():
                        tmp = df_pred.copy()
                        tmp["_ts_hour2"] = ts.dt.floor("H")
                        pivot = tmp.groupby(["_ts_hour2", "predicted_severity"]).size().unstack(fill_value=0).sort_index()

                        import matplotlib.pyplot as plt
                        fig, ax = plt.subplots()
                        # stacked area
                        ax.stackplot(pivot.index, pivot.T.values, labels=pivot.columns)
                        ax.set_title(f"Timeline empilée des severities prédites (par heure) – {ts_col}")
                        ax.set_xlabel("Heure")
                        ax.set_ylabel("count")
                        ax.legend(loc="upper left", ncols=2)
                        st.pyplot(fig)
                        _stacked_done = True
                        break
            if not _stacked_done:
                st.caption("Timeline empilée: colonne timestamp non trouvée / non parseable.")

            # 2) Heatmap agent × predicted severity (Top agents)
            if "agent.name" in df_pred.columns:
                topN = 15
                top_agents_list = (
                    df_pred["agent.name"]
                    .astype(str)
                    .replace({"<NA>": ""})
                    .fillna("")
                )
                top_agents_list = top_agents_list[top_agents_list != ""].value_counts().head(topN).index.tolist()
                if top_agents_list:
                    sub = df_pred[df_pred["agent.name"].astype(str).isin(top_agents_list)].copy()
                    heat = pd.crosstab(sub["agent.name"].astype(str), sub["predicted_severity"].astype(str))

                    import matplotlib.pyplot as plt
                    fig, ax = plt.subplots()
                    im = ax.imshow(heat.values)
                    ax.set_title("Agent × severity prédite (Top 15 agents)")
                    ax.set_xlabel("predicted_severity")
                    ax.set_ylabel("agent.name")
                    ax.set_xticks(range(len(heat.columns)))
                    ax.set_xticklabels(heat.columns, rotation=45, ha="right")
                    ax.set_yticks(range(len(heat.index)))
                    ax.set_yticklabels(heat.index)

                    # annotate counts
                    for i in range(heat.shape[0]):
                        for j in range(heat.shape[1]):
                            ax.text(j, i, int(heat.values[i, j]), ha="center", va="center", fontsize=8)

                    st.pyplot(fig)
                else:
                    st.caption("Heatmap agent × severity: agent.name vide / indisponible.")
            else:
                st.caption("Heatmap agent × severity: colonne agent.name non disponible.")
            # optional: top agents / rules by predicted severity if columns exist
            if "agent.name" in df_pred.columns:
                st.markdown("#### Top agents par severity prédite (Top 10)")
                top_agents = (
                    df_pred.groupby(["predicted_severity", "agent.name"])
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=False)
                    .head(100)
                )
                st.dataframe(top_agents.head(30), use_container_width=True)

            if "rule.id" in df_pred.columns:
                st.markdown("#### Top rule.id par severity prédite (Top 10)")
                top_rules = (
                    df_pred.groupby(["predicted_severity", "rule.id"])
                    .size()
                    .reset_index(name="count")
                    .sort_values("count", ascending=False)
                    .head(100)
                )
                st.dataframe(top_rules.head(30), use_container_width=True)

            # Confusion matrix if ground truth exists
            if "severity" in df_pred.columns and df_pred["severity"].notna().any():
                st.markdown("#### Matrice de confusion (si severity = ground truth)")
                _plot_confusion_matrix(df_pred["severity"], df_pred["predicted_severity"])

        except Exception as e:
            st.exception(e)

    st.divider()
    st.subheader("Voir le log local (jsonl) + télécharger")
    log_path_view = st.text_input(
        "Log à afficher",
        value=st.session_state.get("last_pred_log_path", "logs/predictions_local.jsonl"),
        key="log_path_view",
    )
    last_n = st.slider("Nombre de lignes à afficher", min_value=10, max_value=500, value=200, step=10)

    log_df = _read_last_jsonl(log_path_view, n=int(last_n))
    if log_df.empty:
        st.caption("Aucun log trouvé (ou vide). Lance une prédiction pour générer des logs.")
    else:
        st.dataframe(log_df, use_container_width=True)
        st.download_button(
            "Télécharger le log (jsonl)",
            data=Path(log_path_view).read_bytes(),
            file_name=Path(log_path_view).name,
        )

    st.divider()
    st.subheader("cycle: Prédiction continue depuis l'indexer Wazuh + log local")
    st.caption("Utilise run_prediction_cycle pour lire des événements depuis l'index, prédire, et écrire dans un log local.")

    with st.form("cycle_form"):
        last_ts = st.text_input("last_ts (ISO) - ex: 2026-01-01T00:00:00Z", value="1970-01-01T00:00:00Z")
        cycle_log_path = st.text_input("log_path", value="logs/predictions_cycle.jsonl")
        size = st.number_input("batch size", min_value=1, max_value=1000, value=5, step=1)
        submit_cycle = st.form_submit_button("Lancer run_prediction_cycle")

    if submit_cycle:
        try:
            if not Path(model_path).exists():
                st.error("Modèle introuvable. Corrige le chemin du modèle.")
            else:
                Path(cycle_log_path).parent.mkdir(parents=True, exist_ok=True)
                out = run_prediction_cycle(
                    model_path=model_path,
                    base_url=base_url,
                    username=username,
                    password=password,
                    source_index=source_index,
                    log_path=cycle_log_path,
                    last_ts=last_ts,
                    size=int(size),
                    search_after=None,
                )
                st.success("✅ run_prediction_cycle terminé.")
                st.write(out)

                if Path(cycle_log_path).exists():
                    st.download_button(
                        "Télécharger le log de prédictions (cycle) (.jsonl)",
                        data=Path(cycle_log_path).read_bytes(),
                        file_name=Path(cycle_log_path).name,
                    )
        except Exception as e:
            st.exception(e)

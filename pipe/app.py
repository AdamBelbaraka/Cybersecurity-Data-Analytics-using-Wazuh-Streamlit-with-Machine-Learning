import os
import time
import json
from io import StringIO

import pandas as pd
import joblib
import streamlit as st
import altair as alt
from predicting import predict_dataset

# Styling constants
PRIMARY_COLOR = "#076d27"
BG_COLOR = "#ffffff"

# ------------------ UI ------------------
st.set_page_config(page_title="Dashboard - Severity ML", layout="wide")
# Inject CSS for white background and green accents
st.markdown(
    f"""
    <style>
    /* page background */
    .stApp {{ background-color: {BG_COLOR}; }}

    /* sidebar background + text */
    [data-testid="stSidebar"] > div {{ background-color: {PRIMARY_COLOR}; color: #ffffff; padding-top: 1rem; }}
    [data-testid="stSidebar"] * {{ color: #ffffff !important; }}

    /* sidebar buttons (inverted) */
    [data-testid="stSidebar"] .stButton>button, [data-testid="stSidebar"] .stDownloadButton>button {{
        background-color: #ffffff !important;
        color: {PRIMARY_COLOR} !important;
        border-radius: 6px;
    }}

    /* primary buttons */
    .stButton>button, .stDownloadButton>button {{
        background-color: {PRIMARY_COLOR} !important;
        color: #ffffff !important;
        border-radius: 6px;
        border: none;
    }}

    /* headings */
    h1, h2, h3 {{ color: {PRIMARY_COLOR} !important; }}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Dashboard Streamlit — Severity Model")

# ------------------ Helpers ------------------
@st.cache_data
def load_csv(path):
    return pd.read_csv(path, low_memory=False)

@st.cache_resource
def load_model(payload_path="models/best_severity_model.joblib"):
    return joblib.load(payload_path)

@st.cache_data
def load_metrics(path="models/severity_metrics.json"):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ------------------ UI ------------------

st.sidebar.title("Navigation")
page = st.sidebar.radio("Aller à", ["Aperçu", "Modèle & Métriques", "Prédiction", "Exports", "À propos"]) 

# Default dataset path
DEFAULT_CSV = "wazuh_logs.csv"

if page == "Aperçu":
    st.header("Aperçu des données")
    st.write("Charge un CSV (par défaut `wazuh_logs.csv`) pour inspecter et filtrer les logs.")

    uploaded = st.file_uploader("Charger un fichier CSV", type=["csv"])
    if uploaded is not None:
        df = pd.read_csv(uploaded, low_memory=False)
    else:
        if os.path.exists(DEFAULT_CSV):
            df = load_csv(DEFAULT_CSV)
            st.success(f"Chargé: {DEFAULT_CSV} — {len(df)} lignes")
        else:
            st.warning("Aucun fichier par défaut trouvé. Chargez un CSV pour commencer.")
            df = None

    if df is not None:
        st.subheader("Aperçu")
        st.dataframe(df.head(200))

        with st.expander("Colonnes"):
            st.write(list(df.columns))

        st.subheader("Filtrer les données")
        col_to_filter = st.selectbox("Choisir une colonne pour filtrer (ou 'Aucun')", ["Aucun"] + list(df.columns))
        if col_to_filter and col_to_filter != "Aucun":
            unique_vals = df[col_to_filter].dropna().unique().tolist()[:200]
            sel = st.multiselect("Valeurs", unique_vals)
            if sel:
                st.dataframe(df[df[col_to_filter].isin(sel)].head(200))


elif page == "Modèle & Métriques":
    st.header("Informations sur le modèle")
    try:
        payload = load_model()
    except Exception as e:
        st.error(f"Impossible de charger le modèle: {e}")
        payload = None

    if payload is not None:
        model = payload.get("model")
        feature_cols = payload.get("feature_cols", [])
        st.subheader("Résumé")
        st.write(f"Model object: `{type(model).__name__}`")
        c1, c2 = st.columns([1, 1])
        c1.metric("Features attendues", len(feature_cols))
        metrics = load_metrics()
        if metrics and isinstance(metrics, dict):
            acc = metrics.get("accuracy") or metrics.get("acc") or metrics.get("f1_score")
            if acc is not None:
                c2.metric("Accuracy / F1", f"{acc:.2%}")
            else:
                c2.metric("Métriques disponibles", ", ".join(list(metrics.keys())[:3]))
        else:
            c2.metric("Métriques", "N/A")

        with st.expander("Liste des features"):
            st.write(feature_cols)

        st.subheader("Métriques enregistrées")
        if metrics is None:
            st.info("Aucun fichier `models/severity_metrics.json` trouvé.")
        else:
            st.json(metrics)


elif page == "Prédiction":
    st.header("Effectuer des prédictions")
    st.write("Chargez un CSV pour effectuer des prédictions par lot, ou exécutez le modèle sur le dataset par défaut.")

    uploaded = st.file_uploader("CSV pour prédiction (optionnel)", type=["csv"], key="pred")
    dataset_path = None
    if uploaded is not None:
        # save to a temp buffer so the predicting.predict_dataset can read from a path
        df_input = pd.read_csv(uploaded, low_memory=False)
        st.write(f"Fichier chargé: {len(df_input)} lignes")
        # keep in memory for display and let user run prediction directly
    else:
        if os.path.exists(DEFAULT_CSV):
            df_input = load_csv(DEFAULT_CSV)
            st.write(f"Dataset par défaut: {DEFAULT_CSV} — {len(df_input)} lignes")
        else:
            st.warning("Aucun dataset disponible. Chargez un CSV pour lancer des prédictions.")
            df_input = None

    if df_input is not None:
        st.subheader("Aperçu des données d'entrée")
        st.dataframe(df_input.head(200))

        if st.button("Lancer la prédiction" , key="run_pred"):
            try:
                # If we have an uploaded file, write to temp file so predict_dataset can read a path
                tmp_path = "__tmp_for_pred__.csv"
                df_input.to_csv(tmp_path, index=False)

                start = time.time()
                out = predict_dataset("models/best_severity_model.joblib", tmp_path)
                dur = time.time() - start

                st.success(f"Prédictions terminées en {dur:.2f}s — {len(out)} lignes")
                st.subheader("Aperçu des résultats")
                st.dataframe(out.head(200))

                # Plots
                st.subheader("Distribution des labels et scores")
                if "ml_label" in out.columns:
                    counts = out["ml_label"].value_counts().rename_axis("ml_label").reset_index(name="count")
                    bar = alt.Chart(counts).mark_bar(color=PRIMARY_COLOR).encode(
                        x=alt.X("ml_label:N", sort="-y", title="Label"),
                        y=alt.Y("count:Q", title="Nombre"),
                        tooltip=["ml_label:N", "count:Q"],
                    ).properties(width=450, height=300)
                    st.altair_chart(bar, use_container_width=True)
                if "risk_score" in out.columns:
                    hist = alt.Chart(out).mark_bar(opacity=0.7, color=PRIMARY_COLOR).encode(
                        alt.X("risk_score:Q", bin=alt.Bin(maxbins=40), title="Risk score"),
                        y='count()',
                        tooltip=[alt.Tooltip('count()', title='Count')]
                    ).properties(width=450, height=300)
                    st.altair_chart(hist, use_container_width=True)
                    st.write(out["risk_score"].describe())

                # Allow download
                csv = out.to_csv(index=False)
                st.download_button("Télécharger les prédictions (CSV)", csv, file_name="predictions.csv")

                # Save to exports
                os.makedirs("exports", exist_ok=True)
                out_path = f"exports/predictions_{int(time.time())}.csv"
                out.to_csv(out_path, index=False)
                st.write(f"Fichier sauvegardé: `{out_path}`")

                # cleanup tmp
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

            except Exception as e:
                st.error(f"Erreur pendant la prédiction: {e}")


elif page == "Exports":
    st.header("Fichiers exports")
    st.write("Liste des CSV dans le dossier `exports/`")
    files = []
    if os.path.exists("exports"):
        files = [f for f in os.listdir("exports") if f.endswith(".csv")]
    if files:
        for f in files:
            st.write(f)
            with open(os.path.join("exports", f), "rb") as fh:
                st.download_button(f"Télécharger {f}", fh, file_name=f)
    else:
        st.info("Aucun fichier dans `exports/`")

else:
    st.header("Credist")
    st.write("Made By : " \
    "Adam Belbaraka" \
    "Ayoub Elmortaji" \
    "Walid Kebiyer" \
    "Oumama Aliouat")
    st.write("Usage: `pip install -r requirements.txt` puis `streamlit run app.py`")

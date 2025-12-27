## Comme l’architecture Wazuh n’est pas encore totalement prête, je vais d’abord travailler avec des logs simulés qui respectent le plus possible le format des logs réels afin de développer toute la chaîne ML dès maintenant. Concrètement, je vais préparer un dataset, construire et entraîner un modèle de classification capable de prédire la sévérité des événements et le type d’attaque, puis sauvegarder le modèle et le preprocessing




━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PIPELINE D’APPRENTISSAGE
(ON OUBLIE LA PREDICTION POUR LE MOMENT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Objectif
Mettre en place un pipeline complet d’apprentissage ML capable de prédire
1 la sévérité des logs (critical, high, medium, low)
2 le type d’attaque (ddos, privilege escalation, phishing, brute force, normal)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟦 ETAPE 1 — GENERATION / CONSTRUCTION DU DATASET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 But
Créer des logs simulés au format Wazuh (structure complète) afin de commencer sans l’architecture

📥 Entrée
Générateur de logs simulés (JSONL)

📤 Sortie
data/logs_simules.jsonl

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟨 ETAPE 2 — DEFINIR LES LABELS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 But
Créer les cibles du modèle

🏷 Labels à ajouter
severity = critical high medium low
attack_type = ddos privilege_escalation phishing brute_force normal

📤 Sortie
data/dataset_labellise.jsonl

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟩 ETAPE 3 — PRETRAITEMENT ET PREPARATION DU DATASET
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 But
Transformer les logs en données exploitables par le modèle ML

⚙ Actions
🧹 Nettoyage
❓ Valeurs manquantes
🧩 Sélection champs utiles
🔤 Encodage (catégoriel)
📝 Vectorisation texte si besoin (TF-IDF)
📅 Extraction features depuis timestamp

📤 Sortie
data/dataset_train.csv

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟪 ETAPE 4 — ENTRAINEMENT DU MODELE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 But
Entraîner un modèle de classification

⚙ Actions
📊 Split Train Test
🧠 Training du modèle
💾 Sauvegarde du modèle et du preprocessing

📤 Sortie
models/model.pkl
models/preprocessor.pkl

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟥 ETAPE 5 — EVALUATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 But
Mesurer la performance du modèle

📈 Métriques
Accuracy
Precision
Recall
F1 Score
Confusion Matrix

📤 Sortie
data/results/metrics.json
data/results/report.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟫 ETAPE 6 — VERSIONNING ET SAUVEGARDE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 But
Préparer un modèle stable et réutilisable pour l’intégration future

📦 À sauvegarder
model_v1.pkl
preprocessor_v1.pkl
features_used.json
model_version.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📌 CE QUE TU DOIS FAIRE MAINTENANT (CONCRET)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1 ✅ Générer logs_simules.jsonl (format Wazuh complet)
2 ✅ Ajouter labels severity + attack_type
3 ✅ Transformer en dataset_train.csv (features + labels)
4 ✅ Entraîner un modèle baseline
5 ✅ Évaluer et sauvegarder modèle + preprocessing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


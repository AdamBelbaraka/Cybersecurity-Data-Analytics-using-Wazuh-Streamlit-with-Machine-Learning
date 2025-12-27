Dans le cadre du pipeline d’apprentissage, j’ai commencé par générer des logs simulés au format proche de Wazuh (JSONL), incluant des événements normaux et des événements d’attaque. Chaque log contient une structure stable (timestamp, agent, rule, decoder, data, full_log) ainsi que deux labels (severity et attack_type) utilisés pour l’entraînement supervisé. Ensuite, j’ai converti ces logs JSONL en un dataset tabulaire CSV en extrayant les champs utiles et en conservant les valeurs manquantes comme vides afin de gérer le traitement plus tard. À partir de ce CSV, j’ai lancé la phase de preprocessing où je vérifie la qualité des données (valeurs manquantes, distribution des classes) et je prépare la matrice d’entrée du modèle. Pour le baseline, j’ai décidé d’ignorer les champs trop incomplets comme command et status, puis j’utilise un pipeline sklearn (ColumnTransformer) qui applique TF-IDF sur full_log (texte), OneHotEncoder sur les champs catégoriels (OS, decoder, protocol, user, process, etc.) et conserve les champs numériques (ports, rule_level). J’ai également analysé le déséquilibre des classes (normal majoritaire) et identifié la nécessité d’utiliser une stratégie adaptée au training (split stratifié et class_weight balanced)











!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

la partie des features khasha chi aproche akhra hitach m3rftch ach gandir f les partie fuul_log hit ghatgenerer bsaf dial features -- Shape apres preprocessing: (10000, 3053)
# README – Pipeline ML Wazuh

## 1. Pipeline d'apprentissage

- **Créer un index dédié** dans Wazuh Manager via **Indexer API** pour les données ML à traiter par le moteur ML.  
- **Envoyer des logs de données simulées** vers l’index Wazuh Manager via Indexer API  
  - (ici simulés à partir de l’endpoint hébergeant l’apprentissage ML)  

**TO COMPLETE :**  
- Cas réel = les agents des endpoints monitorés envoient des logs vers l’index ML data en respectant le format ndjson.  

- **Récupérer les données** depuis l’index ML (json/ndjson), parser en DataFrame.  

**TO COMPLETE :**  
- Intégrer le ML pipeline train : entraîner le modèle avec les données dans la DataFrame, sauvegarder le modèle entraîné dans `model.pkl`.  

### Contraintes à prendre en considération avec le dataset réel
- Format des données  
- Rate limits de l’API  

---

## 2. Pipeline de prédiction

- Lire les données depuis l’index Wazuh Manager, effectuer les prédictions, envoyer les résultats au Manager pour générer des alertes sur les dashboards.  

### 2.1 Listening simulé => Trigger de pipeline de prédiction

**Option choisie :**  
- Polling en boucle de l’index `wazuh-archives-4.x` pour détection de nouveaux logs entrants  
  - (simulé par envoi de logs dans l’étape précédente)

**Inconvénients :**  
- Simple mais pas temps réel, convient pour PoC ou traitement de tous les logs archivés.  
- La prédiction ML est déclenchée après les règles classiques → on ne travaille pas sur les raw logs entrants mais sur des événements déjà traités.  
- Latence introduite + charge supplémentaire sur Elasticsearch + nécessité de gérer les doublons.  
- Pas de lien direct avec la détection réelle des événements.  

**A COMPLETER :**  

**Option testée :**  
- **2️⃣ Liaison via Wazuh Manager API**  
  - Problème : il faut définir des décodeurs custom, erreurs fréquentes et documentation syntaxe limitée  

**Autres options :**  
- Chaque agent Wazuh exécute localement le code ML dès qu’un log est généré et envoyé au Manager  
  - Inconvénient : pas de centralisation  
- **4️⃣ Déclenchement ML directement sur le Manager**  
  - Changement de conception : le code ML est sur le noeud Manager  
- **Filebeat / Logstash streaming vers ML**  
  - À chercher faisabilité de cette option  
  - Filebeat ou Logstash transmet les logs en streaming vers le pipeline ML  
  - Temps réel, traitement proche des logs entrants  
  - Nécessite un pipeline additionnel mais très efficace pour les environnements volumineux  

**Remarque :**  
- Nous avons simulé l’envoi des données vers l’index sur lequel on a le listening triggers  

---

### 2.2 Prédiction

- Simulée en ajoutant des colonnes de prédiction dans le DataFrame  

**TO COMPLETE :**  
- Cas réel : charger le modèle entraîné (`model.pkl`) et faire des prédictions sur les nouveaux logs entrants  

---

### 2.3 Envoi des résultats de prédiction à Wazuh Manager

**Option choisie :**  
- Écriture des résultats de prédiction dans un fichier de log local  
- Ajouter le path de fichier dans `ossec.conf` de l’agent  

**TO FIX :**  
- `write_prediction events format` (voir code, pour ne pas ajouter les champs agent explicitement)  

**Fonctionnement :**  
- L’agent transmet les prédictions comme tous les autres logs normaux au Manager  

**Sur le Manager :**  
- **Décodage :** pas de décodeurs custom, mais adaptation du format des logs pour qu’ils soient reconnus par les décodeurs existants (decodeur par défaut json)  
- **Rules matching :** custom rules sur le Manager pour matcher les logs de prédiction et générer des alertes si besoin  

**Exemple de règles :**  

```xml
<group name="ml-pipeline">

    <!-- Base rule: any ML prediction  -->
    <rule id="100100" level="12">
        <decoded_as>json</decoded_as>
        <field name="event_type">ml_prediction</field>
        <description>ML prediction ingested</description>
    </rule>

    <!-- Specific rule: malicious label  -->
    <rule id="100110" level="12">
        <if_sid>100100</if_sid>
        <field name="ml_label">malicious</field>
        <description>ML flagged malicious activity</description>
    </rule>

</group>


=> alertes visibles sur wazuh dashboard, sur l index wazuh-alerts-*


* inconvenients de l utilisation de fichier local :
    - Gestion des fichiers et doublons (Nécessité de gérer la rotation des fichiers ou suppression après lecture.)
     
        


+++ : posera t il prob que l agent envoie des logs normaux + logs de prediction via le meme canal vers le manager ?

      
            
* autres options:
          A COMPLETER : a chercher faisabilite de ces options ou autres 

            - Syslog direct vers Manager

            - API Wazuh Manager

            - Filebeat / Logstash vers Manager





## - A COMPLETER : separation d'index et choix justifie des index 




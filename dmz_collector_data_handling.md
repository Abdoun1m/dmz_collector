# DMZ Collector — Réception, buffering, contrôle et forwarding OT vers Splunk

## 1. Introduction

Le DMZ Collector est le relais de sécurité positionné dans la zone DMZ entre la collecte OT et la couche IT/SIEM.

Rôle principal :
- recevoir les événements normalisés en provenance de l’OT Collector ;
- conserver une trace locale et une capacité de buffering/spool ;
- appliquer un forwarding contrôlé vers Splunk HEC ;
- maintenir la séparation de confiance entre OT et IT.

La présence d’un relais DMZ évite un flux direct OT → Splunk et réduit l’exposition des actifs industriels à la zone IT.

## 2. Position dans l’architecture de type Purdue

Chaîne validée : **OT Sources → OT Collector → DMZ Collector → Splunk (index=ot_security)**.

Dans une logique Purdue/ISA-95, le DMZ Collector joue le rôle de point de transit contrôlé entre niveaux OT et IT/SIEM.

```mermaid
flowchart LR
    A[Sources OT\nFirewall, PLC, SCADA, OPC UA, GDS, EWS] --> B[OT Collector (zone OT)\nCollecte + normalisation]
    B --> C[DMZ Collector (zone DMZ)\nStockage + spool + forwarding contrôlé]
    C --> D[Splunk (zone IT/SIEM)\nindex=ot_security]
```

Cette architecture évite le trafic direct OT→Splunk et impose un contrôle intermédiaire (segmentation, audit, résilience).

## 3. Responsabilités du DMZ Collector

Le DMZ Collector assure les fonctions suivantes :
- réception des événements depuis l’OT Collector (API exposée sur `0.0.0.0:9000`) ;
- préservation des champs normalisés et métadonnées OT ;
- stockage local des événements dans `/data/events.jsonl` ;
- mise en spool dans `/data/spool/events.jsonl` si forwarding indisponible ;
- forwarding vers Splunk HEC quand la sortie SIEM est disponible ;
- exposition API/UI locale pour supervision et validation ;
- contribution à l’auditabilité inter-zones.

## 4. Modèle de données en entrée

Le DMZ Collector attend un événement déjà normalisé côté OT Collector.

### 4.1 Structure attendue

| Champ | Rôle | Remarque |
|---|---|---|
| `timestamp` | Horodatage de l’événement source | fourni par la couche OT |
| `received_at` | Horodatage de réception | peut être enrichi/actualisé selon pipeline |
| `zone` | Zone d’origine | attendu : `OT` |
| `source_type` | Type de source normalisé | ex. `plc`, `scada`, `firewall` |
| `asset_name` | Nom de l’actif | utile corrélation SOC |
| `asset_ip` | IP de l’actif | pivot investigation |
| `severity` | Niveau de sévérité | normalisé OT |
| `protocol` | Protocole d’origine | ex. `syslog`, `http` |
| `event_category` | Catégorie métier/sécurité | normalisée |
| `message` | Identifiant/message canonique | base dashboards/alertes |
| `raw` | Charge brute conservée | preuve forensique |
| `tags.*` | Métadonnées analytiques | préservées/forwardées |

### 4.2 Exemple JSON (événement reçu)

```json
{
  "id": "evt-ot-1710000100-0001",
  "timestamp": "2026-05-17T10:15:00Z",
  "received_at": "2026-05-17T10:15:01Z",
  "zone": "OT",
  "source_type": "plc",
  "asset_name": "OpenPLC Main",
  "asset_ip": "192.168.1.20",
  "severity": "warning",
  "protocol": "syslog",
  "event_category": "authentication",
  "message": "plc_login_attempt",
  "raw": "<raw source payload>",
  "tags": {
    "normalized": true,
    "normalization_source": "logs_by_sources_md",
    "parser_version": "v2.logs_by_sources_md",
    "splunk_sourcetype": "labshock:ot:plc",
    "siem_index_hint": "ot_security",
    "collector_decision": "store_and_forward",
    "forwarding_status": "queued",
    "matched_rule_id": "rule-plc-auth-01"
  }
}
```

## 5. Préservation des champs

Les champs suivants produits côté OT Collector doivent être conservés lors du passage DMZ :
- `tags.normalized`
- `tags.normalization_source`
- `tags.parser_version`
- `tags.splunk_sourcetype`
- `tags.siem_index_hint`
- `tags.alert_candidate`
- `tags.collector_decision`
- `tags.forwarding_status`
- `tags.matched_rule_id`
- tags spécifiques source : `src_ip`, `dst_ip`, `target`, `target_ip`, `user`, `node_id`, `application_uri`

Objectif : préserver l’intégrité sémantique OT pour l’exploitation SIEM sans re-normalisation destructive en DMZ.

## 6. Mécanisme de stockage et spool

### 6.1 Fichiers
- Événements stockés : `/data/events.jsonl`
- File de spool : `/data/spool/events.jsonl`

### 6.2 Différence fonctionnelle
- `events.jsonl` : journal local des événements reçus/acceptés en DMZ.
- `spool/events.jsonl` : tampon de reprise pour les événements en attente de forwarding (ou à réémettre).

### 6.3 Rôle en résilience
Le spool est critique lorsque Splunk est temporairement indisponible (route, HEC, TLS, token, maintenance).

Bénéfices :
- continuité de collecte DMZ ;
- réduction du risque de perte ;
- reprise différée du forwarding ;
- traçabilité en cas d’incident.

## 7. Forwarding Splunk HEC

### 7.1 Paramètres de principe
- URL HEC : endpoint Splunk HEC configuré côté DMZ Collector.
- Authentification : token Splunk HEC.
- Index cible : `ot_security`.
- Source envoyée : `labshock_dmz_collector`.
- Sourcetype : prioritairement dérivé de `tags.splunk_sourcetype`.

### 7.2 TLS et validation certificat
- Le comportement précis de vérification TLS dépend de la configuration effective du déploiement.
- Politique exacte de hardening TLS : **À valider**.

### 7.3 Retry / réémission
- Le principe de buffering/spool est établi.
- Stratégie exacte (backoff, fréquence, limites, ordre strict) : **À valider**.

## 8. Rôle syslog firewall, si activé

Le DMZ Collector peut également exposer un listener syslog firewall en UDP 5514 si cette option est activée.

Points confirmés :
- existence possible du listener 5514 dans certains déploiements.

Points non confirmés :
- matrice complète des formats/parseurs sur ce listener ;
- règles exactes de normalisation dédiées ;
- interaction détaillée avec le pipeline OT→DMZ existant.

Ces éléments sont **À valider**.

## 9. Cycle de vie bout-en-bout des événements

### 9.1 Cas : PLC login attempt
- Événement OT source : tentative d’authentification PLC.
- OT Collector : normalise en `message=plc_login_attempt`, `source_type=plc`, `tags.splunk_sourcetype=labshock:ot:plc`.
- DMZ Collector : reçoit, stocke dans `/data/events.jsonl`, spool si nécessaire, forward vers Splunk.
- Champs Splunk recherchables : `source_type`, `asset_name`, `severity`, `message`, `tags.*`.
- Usage dashboard/alerte : suivi des tentatives d’accès et détection brute force.

### 9.2 Cas : SCADA PLC connection attempt
- Événement OT source : tentative de connexion SCADA vers PLC.
- OT Collector : `message=scada_plc_connection_attempt`, `source_type=scada`, sourcetype SCADA.
- DMZ Collector : rôle de relais contrôlé + buffering.
- Champs Splunk : `event_category`, `asset_ip`, `tags.collector_decision`.
- Usage dashboard/alerte : santé des flux SCADA/PLC, détection écarts de connectivité.

### 9.3 Cas : Firewall block
- Événement OT source : blocage firewall.
- OT Collector : `message=firewall_block`, `source_type=firewall`, `labshock:net:firewall`.
- DMZ Collector : conservation et forwarding prioritaire via pipeline.
- Champs Splunk : `source_type=firewall`, `message=firewall_block`, tags réseau si présents (`src_ip`, `dst_ip`).
- Usage dashboard/alerte : événements de sécurité réseau critiques.

### 9.4 Cas : OPC UA Modbus failure
- Événement OT source : échec de communication Modbus côté OPC UA.
- OT Collector : `message=modbus_connection_failed`, `source_type=opcua`.
- DMZ Collector : stockage local puis forwarding SIEM.
- Champs Splunk : `source_type=opcua`, `event_category`, `severity`.
- Usage dashboard/alerte : détection dégradation disponibilité OT.

### 9.5 Cas : GDS certificate expiry critical
- Événement OT source : expiration critique certificat GDS.
- OT Collector : `message=certificate_expiry_critical`, `source_type=gds_agent`, sourcetype GDS.
- DMZ Collector : relais sécurisé vers Splunk, maintien de `tags.parser_version` et tags PKI.
- Champs Splunk : `message`, `source_type`, `asset_name`, tags liés PKI.
- Usage dashboard/alerte : priorisation cyber PKI/identités machine.

## 10. Commandes de validation

> Adapter les noms de conteneur/interface selon l’environnement réel.

### 10.1 Vérifier le conteneur DMZ Collector

```bash
docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' | grep dmz_collector
```

### 10.2 Vérifier IP/route après attachement OVS

```bash
docker exec dmz_collector sh -lc 'ip addr; ip route'
```

### 10.3 Vérifier l’écoute API DMZ sur 9000

```bash
docker exec dmz_collector sh -lc 'ss -lntup | grep :9000'
```

### 10.4 Vérifier le fichier d’événements

```bash
docker exec dmz_collector sh -lc 'ls -lh /data/events.jsonl; tail -n 20 /data/events.jsonl'
```

### 10.5 Vérifier le spool

```bash
docker exec dmz_collector sh -lc 'ls -lh /data/spool/events.jsonl; tail -n 20 /data/spool/events.jsonl'
```

### 10.6 Tester la santé API

```bash
curl -s http://127.0.0.1:9000/health | jq
```

### 10.7 Vérifier la connectivité HEC depuis DMZ

```bash
docker exec dmz_collector sh -lc '
wget -S -O- --timeout=5 \
  --header="Authorization: Splunk $SPLUNK_HEC_TOKEN" \
  --header="Content-Type: application/json" \
  --post-data="{\"index\":\"ot_security\",\"sourcetype\":\"labshock:test\",\"source\":\"dmz_collector_check\",\"event\":{\"message\":\"hec connectivity test\"}}" \
  --no-check-certificate \
  "$SPLUNK_HEC_URL" 2>&1 || true
'
```

### 10.8 Vérifier les événements récemment forwardés

```bash
curl -s 'http://127.0.0.1:9000/events?limit=200' | jq '.[] | {id, source_type, message, tags: .tags}'
```

## 11. Validation Splunk (SPL)

### 11.1 Tous les événements forwardés par le DMZ Collector

```spl
index=ot_security source="labshock_dmz_collector"
| stats count
```

### 11.2 Volumétrie par source_type

```spl
index=ot_security source="labshock_dmz_collector"
| stats count by source_type
| sort - count
```

### 11.3 Couverture sourcetype

```spl
index=ot_security source="labshock_dmz_collector"
| stats count by sourcetype
| sort - count
```

### 11.4 Événements sans sourcetype renseigné

```spl
index=ot_security source="labshock_dmz_collector"
| where isnull(tags.splunk_sourcetype) OR tags.splunk_sourcetype=""
| table _time source_type asset_name message tags.*
```

### 11.5 Suivi forwarding_status

```spl
index=ot_security source="labshock_dmz_collector"
| stats count by tags.forwarding_status
```

### 11.6 Candidats d’alerte

```spl
index=ot_security source="labshock_dmz_collector" tags.alert_candidate=true
| table _time source_type asset_name severity message event_category tags.*
| sort - _time
```

### 11.7 Dernier événement par source_type et asset_name

```spl
index=ot_security source="labshock_dmz_collector"
| stats latest(_time) as last_seen, latest(message) as last_message by source_type, asset_name
| convert ctime(last_seen)
| sort source_type, asset_name
```

## 12. Modes de panne et dépannage

| Symptôme | Cause probable | Vérification | Action corrective |
|---|---|---|---|
| DMZ Collector non joignable | non attaché OVS | IP/route container | réattacher OVS, revalider route |
| Pas de route vers Splunk | routage DMZ incomplet | `ip route`, test HEC | corriger gateway/route DMZ |
| HEC refuse les requêtes | token invalide | code HTTP HEC, logs | corriger token Splunk |
| Erreur TLS HEC | certificat/CA non alignés | logs client + test TLS | ajuster trust store ou mode TLS |
| Pas d’envoi HEC | HEC disabled | variables/env config | activer HEC et redéployer |
| Spool en croissance continue | Splunk indisponible ou rejet HEC | taille `/data/spool/events.jsonl` | corriger connectivité/HEC, surveiller vidange |
| Événements stockés mais non forwardés | pipeline sortie bloqué | comparer events vs Splunk | diagnostiquer forwarding worker |
| Sourcetype absent/erroné | tag OT manquant/non préservé | recherche Splunk ciblée | corriger mapping/préservation tags |
| Doublons | réémission/retry sans dédup stricte | corrélation `id` | ajuster stratégie retry/dedup (**À valider**) |
| OT reachable, Splunk unreachable | cloisonnement/routage IT | tests réseau séparés | maintenir spool, corriger trajet DMZ→IT |

## 13. Rationnel sécurité

Le DMZ Collector apporte :
- **segmentation** : séparation explicite des zones OT et IT ;
- **réduction d’exposition OT** : pas de communication directe OT→SIEM ;
- **egress contrôlé** : unique point de sortie journalisé vers Splunk ;
- **piste d’audit** : conservation locale + métadonnées de décision ;
- **buffering résilient** : maintien de collecte même en panne SIEM ;
- **découplage OT/IT** : limitation des dépendances directes entre couches.

Ce positionnement est cohérent avec les principes Purdue et les bonnes pratiques ICS de défense en profondeur.

## 14. Impact dashboard/readiness

Le DMZ Collector influence directement :
- **fiabilité dashboard** : réduction des pertes via spool ;
- **fraîcheur des événements** : dépendante de la latence de forwarding ;
- **délai de propagation** : hausse possible en mode reprise après panne ;
- **monitoring santé sources** : préservation des champs OT utiles aux vues source-centric ;
- **confiance SIEM** : normalisation OT maintenue jusqu’à Splunk.

En cas de perturbation SIEM, les tableaux peuvent présenter un retard sans perte immédiate si le spool fonctionne.

## 15. Limites connues / backlog

- Stratégie exacte de retry/backoff du forwarding : **À valider**.
- Comportement exact de déduplication côté DMZ : **À valider**.
- Niveau de hardening TLS HEC en production (CA/pinning/mTLS) : **À valider**.
- Détail exact des champs UI DMZ disponibles selon version : **À valider**.
- Rôle détaillé du listener firewall UDP 5514 dans tous les scénarios : **À valider**.

## 16. Conclusion

Le DMZ Collector est la couche de relais SIEM contrôlée et résiliente entre OT et Splunk.

Il conserve la sémantique OT normalisée, assure un stockage local et un mécanisme de spool, puis forwarde vers Splunk de manière gouvernée, conformément aux principes de segmentation industrielle OT→DMZ→IT.

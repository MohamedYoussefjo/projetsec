# Kibana — dashboards IfSecurity

## Contenu

- `dashboards.ndjson` — 2 dashboards + 16 visualisations + 2 index patterns prêts à importer
- `generate_dashboards.py` — régénère le `.ndjson` (si tu veux modifier la structure)
- `import.sh` — pousse le `.ndjson` dans ton Kibana via l'API
- `export.sh` — réexporte tout ce que tu as construit dans Kibana

## Import en une commande

```bash
chmod +x kibana/*.sh
./kibana/import.sh
```

Le script attend que Kibana réponde sur `localhost:5601`, puis importe tout
avec `overwrite=true`. À la fin, ouvre :

- **IfSecurity — SSH brute-force mitigation** : `http://localhost:5601/app/dashboards#/view/if27-ssh-dashboard`
- **IfSecurity — Web login mitigation** : `http://localhost:5601/app/dashboards#/view/if27-web-dashboard`

## Import manuel via l'UI

1. Kibana → **Stack Management** → **Saved Objects**
2. **Import** (bouton en haut à droite)
3. Coche **Automatically overwrite all conflicts**
4. Sélectionne `dashboards.ndjson` → Import

## Ce que tu obtiens

### Dashboard SSH — `IfSecurity — SSH brute-force mitigation`

| Position | Visualisation |
|---|---|
| Haut x4 | KPIs : Total events, Failed auth, Successful auth, Burst summaries |
| Milieu | Timeline événements (split par event_type) |
| Bas x3 | Pie event types · Bar top IPs attaquantes · Bar top usernames testés |

### Dashboard Web — `IfSecurity — Web login mitigation`

| Position | Visualisation |
|---|---|
| Haut x4 | KPIs : Total events, Failed logins, Account lockouts, Critical risk |
| Milieu | Timeline événements (split par event_type) |
| Bas x3 | Pie event types · Bar top IPs · Bar top usernames |

## Modifier puis sauvegarder

Modifie les dashboards directement dans Kibana, puis :

```bash
./kibana/export.sh
git add kibana/dashboards.ndjson
git commit -m "Update dashboards"
```

Tu réimporteras avec `./kibana/import.sh` à tout moment.

## Auto-import au démarrage (optionnel)

Ajoute ce service à `docker-compose.yml` pour que Kibana se rebuilde tout
seul après un `docker compose down -v` :

```yaml
kibana-init:
  image: curlimages/curl:8.5.0
  container_name: kibana-init
  depends_on:
    - kibana
  volumes:
    - ./kibana:/work
  entrypoint: >
    sh -c "
      until curl -sf http://kibana:5601/api/status >/dev/null; do
        sleep 3;
      done;
      curl -sf -X POST 'http://kibana:5601/api/saved_objects/_import?overwrite=true'
        -H 'kbn-xsrf: true' --form file=@/work/dashboards.ndjson
        && echo 'imported'
    "
  restart: "no"
```

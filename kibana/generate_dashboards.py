"""
Generate Kibana 7.17 saved-objects (.ndjson) for IfSecurity.

Run:
    python kibana/generate_dashboards.py > kibana/dashboards.ndjson

Then in Kibana → Stack Management → Saved Objects → Import → upload the file.

Generates:
  • 2 index-patterns   : if27-ssh-*, if27-web-*
  • SSH dashboard with 7 visualizations
  • Web dashboard with 7 visualizations
"""

import json
import sys


# ─── stable IDs so re-imports overwrite cleanly ────────────────────────────
IP_SSH  = "if27-ssh-pattern"
IP_WEB  = "if27-web-pattern"
DASH_SSH = "if27-ssh-dashboard"
DASH_WEB = "if27-web-dashboard"


# ─── helpers ───────────────────────────────────────────────────────────────
def index_pattern(id_, title):
    return {
        "id": id_,
        "type": "index-pattern",
        "attributes": {
            "title": title,
            "timeFieldName": "@timestamp",
        },
        "references": [],
    }


def search_source(ip_ref):
    return json.dumps({
        "query": {"query": "", "language": "kuery"},
        "filter": [],
        "indexRefName": ip_ref,
    })


def visualization(id_, title, vis_type, vis_state, index_pattern_id):
    return {
        "id": id_,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps({"title": title, "type": vis_type, **vis_state}),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": search_source(
                    "kibanaSavedObjectMeta.searchSourceJSON.index"
                )
            },
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": index_pattern_id,
            }
        ],
    }


# ─── vis builders ──────────────────────────────────────────────────────────
def vis_metric_count(id_, title, label, ip_id, filter_kql=None):
    aggs = [{
        "id": "1",
        "enabled": True,
        "type": "count",
        "schema": "metric",
        "params": {"customLabel": label},
    }]
    vis_state = {
        "params": {
            "metric": {
                "metricColorMode": "None",
                "colorSchema": "Green to Red",
                "labels": {"show": True},
                "style": {"bgColor": False, "fontSize": 50},
                "percentageMode": False,
            },
            "addTooltip": True,
            "addLegend": False,
        },
        "aggs": aggs,
    }
    obj = visualization(id_, title, "metric", vis_state, ip_id)
    if filter_kql:
        obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps({
            "query": {"query": filter_kql, "language": "kuery"},
            "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        })
    return obj


def vis_pie(id_, title, field, ip_id, size=10):
    vis_state = {
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                "field": field, "size": size, "order": "desc", "orderBy": "1",
                "otherBucket": False, "missingBucket": False,
            }},
        ],
    }
    return visualization(id_, title, "pie", vis_state, ip_id)


def vis_top_terms_bar(id_, title, field, ip_id, size=10):
    vis_state = {
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                              "show": True, "scale": {"type": "linear"}, "labels": {"show": True},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "type": "value", "position": "bottom",
                           "show": True, "scale": {"type": "linear"}, "labels": {"show": True},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                              "data": {"id": "1", "label": "Count"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True,
            "addLegend": False,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                "field": field, "size": size, "order": "desc", "orderBy": "1",
            }},
        ],
    }
    return visualization(id_, title, "horizontal_bar", vis_state, ip_id)


def vis_timeline(id_, title, ip_id, split_field=None, filter_kql=None):
    aggs = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {
            "field": "@timestamp", "interval": "auto", "min_doc_count": 1,
        }},
    ]
    if split_field:
        aggs.append({
            "id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {
                "field": split_field, "size": 5, "order": "desc", "orderBy": "1",
            },
        })
    vis_state = {
        "params": {
            "type": "line",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "scale": {"type": "linear"}, "labels": {"show": True},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "type": "value", "position": "left",
                           "show": True, "scale": {"type": "linear"}, "labels": {"show": True},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "line", "mode": "normal",
                              "data": {"id": "1", "label": "Count"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True,
                              "interpolate": "linear"}],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
        },
        "aggs": aggs,
    }
    obj = visualization(id_, title, "line", vis_state, ip_id)
    if filter_kql:
        obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps({
            "query": {"query": filter_kql, "language": "kuery"},
            "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        })
    return obj


# ─── dashboard builder ─────────────────────────────────────────────────────
def dashboard(id_, title, panels):
    """panels = list of (vis_id, x, y, w, h)."""
    panels_json = []
    refs = []
    for i, (vis_id, x, y, w, h) in enumerate(panels, 1):
        ref_name = f"panel_{i}"
        panels_json.append({
            "version": "7.17.22",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {},
            "panelRefName": ref_name,
        })
        refs.append({"name": ref_name, "type": "visualization", "id": vis_id})
    return {
        "id": id_,
        "type": "dashboard",
        "attributes": {
            "title": title,
            "hits": 0,
            "description": title,
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({
                "useMargins": True, "syncColors": False, "hidePanelTitles": False
            }),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": ""},
                    "filter": [],
                })
            },
        },
        "references": refs,
    }


# ─── generate all objects ──────────────────────────────────────────────────
def main():
    objects = []

    # Index patterns ───────────────────────────────────────────────────────
    objects.append(index_pattern(IP_SSH, "if27-ssh-*"))
    objects.append(index_pattern(IP_WEB, "if27-web-*"))

    # ─── SSH visualizations ───────────────────────────────────────────────
    ssh_vis = []

    ssh_vis.append(vis_metric_count(
        "if27-ssh-vis-total", "SSH — Total events", "Events", IP_SSH))
    ssh_vis.append(vis_metric_count(
        "if27-ssh-vis-failed", "SSH — Failed auth", "Failed",
        IP_SSH, filter_kql="event_type:ssh_failed_*"))
    ssh_vis.append(vis_metric_count(
        "if27-ssh-vis-success", "SSH — Successful auth", "Success",
        IP_SSH, filter_kql="event_type:ssh_accepted_*"))
    ssh_vis.append(vis_metric_count(
        "if27-ssh-vis-bursts", "SSH — Brute-force bursts", "Bursts",
        IP_SSH, filter_kql="event_type:ssh_burst_summary"))

    ssh_vis.append(vis_pie(
        "if27-ssh-vis-events", "SSH — Event types", "event_type.keyword", IP_SSH))
    ssh_vis.append(vis_top_terms_bar(
        "if27-ssh-vis-top-ips", "SSH — Top attacking IPs", "source_ip.keyword", IP_SSH))
    ssh_vis.append(vis_top_terms_bar(
        "if27-ssh-vis-top-users", "SSH — Top usernames tested", "username.keyword", IP_SSH))
    ssh_vis.append(vis_timeline(
        "if27-ssh-vis-timeline", "SSH — Events over time", IP_SSH,
        split_field="event_type.keyword"))

    objects.extend(ssh_vis)

    # ─── Web visualizations ───────────────────────────────────────────────
    web_vis = []

    web_vis.append(vis_metric_count(
        "if27-web-vis-total", "Web — Total events", "Events", IP_WEB))
    web_vis.append(vis_metric_count(
        "if27-web-vis-failed", "Web — Failed logins", "Failed",
        IP_WEB, filter_kql="event_type:authentication_attempt AND password_success:false"))
    web_vis.append(vis_metric_count(
        "if27-web-vis-locks", "Web — Account lockouts", "Locks",
        IP_WEB, filter_kql="event_type:account_lockout"))
    web_vis.append(vis_metric_count(
        "if27-web-vis-critical", "Web — Critical risk", "Critical",
        IP_WEB, filter_kql="risk_level:critical"))

    web_vis.append(vis_pie(
        "if27-web-vis-events", "Web — Event types", "event_type.keyword", IP_WEB))
    web_vis.append(vis_top_terms_bar(
        "if27-web-vis-top-ips", "Web — Top source IPs", "source_ip.keyword", IP_WEB))
    web_vis.append(vis_top_terms_bar(
        "if27-web-vis-top-users", "Web — Top usernames tested", "username.keyword", IP_WEB))
    web_vis.append(vis_timeline(
        "if27-web-vis-timeline", "Web — Events over time", IP_WEB,
        split_field="event_type.keyword"))

    objects.extend(web_vis)

    # ─── Dashboards ───────────────────────────────────────────────────────
    # Kibana grid: 48 columns wide. KPIs 12 wide, charts 24 wide.
    ssh_panels = [
        ("if27-ssh-vis-total",    0,  0, 12, 6),
        ("if27-ssh-vis-failed",  12,  0, 12, 6),
        ("if27-ssh-vis-success", 24,  0, 12, 6),
        ("if27-ssh-vis-bursts",  36,  0, 12, 6),
        ("if27-ssh-vis-timeline", 0,  6, 48, 12),
        ("if27-ssh-vis-events",   0, 18, 16, 12),
        ("if27-ssh-vis-top-ips", 16, 18, 16, 12),
        ("if27-ssh-vis-top-users", 32, 18, 16, 12),
    ]
    objects.append(dashboard(
        DASH_SSH, "IfSecurity — SSH brute-force mitigation", ssh_panels))

    web_panels = [
        ("if27-web-vis-total",    0,  0, 12, 6),
        ("if27-web-vis-failed",  12,  0, 12, 6),
        ("if27-web-vis-locks",   24,  0, 12, 6),
        ("if27-web-vis-critical", 36, 0, 12, 6),
        ("if27-web-vis-timeline", 0,  6, 48, 12),
        ("if27-web-vis-events",   0, 18, 16, 12),
        ("if27-web-vis-top-ips", 16, 18, 16, 12),
        ("if27-web-vis-top-users", 32, 18, 16, 12),
    ]
    objects.append(dashboard(
        DASH_WEB, "IfSecurity — Web login mitigation", web_panels))

    # ─── Emit NDJSON ──────────────────────────────────────────────────────
    for o in objects:
        print(json.dumps(o, ensure_ascii=False))

    # Optional trailing summary line that Kibana ignores
    print(json.dumps({
        "exportedCount": len(objects),
        "missingRefCount": 0,
        "missingReferences": [],
    }))


if __name__ == "__main__":
    main()

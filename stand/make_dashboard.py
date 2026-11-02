# -*- coding: utf-8 -*-
"""Формирует панель Grafana chart/files/dashboard.json (python stand/make_dashboard.py)."""
import json
import os

DS = {"type": "prometheus", "uid": "prometheus"}
panels = []
_id = [0]


def panel(title, exprs, x, y, w=12, h=8, kind="timeseries", unit=None, desc="", legend="{{pod}}", stat=False):
    _id[0] += 1
    targets = []
    for i, e in enumerate(exprs):
        ex, lg = (e if isinstance(e, tuple) else (e, legend))
        targets.append({"datasource": DS, "expr": ex, "legendFormat": lg, "refId": chr(65 + i)})
    p = {"id": _id[0], "type": "stat" if stat else kind, "title": title, "description": desc, "datasource": DS,
         "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets,
         "fieldConfig": {"defaults": ({"unit": unit} if unit else {}), "overrides": []},
         "options": ({"legend": {"displayMode": "list", "placement": "bottom"}} if not stat else {})}
    panels.append(p)


R = 'role=~"$role"'
panel("Остаток срока аренды", [("credshield_agent_lease_remaining_seconds", "{{pod}}")], 0, 0, unit="s",
      desc="Остаток срока действующей аренды у агента; пилообразный график — замены на 2/3 срока")
panel("Файл учётных данных присутствует", [("credshield_agent_file_present", "{{pod}}")], 12, 0,
      desc="1 — файл есть, 0 — файл удалён по истечении срока (закрытый отказ)")
panel("Выдачи агента, в минуту", [("sum by (result) (rate(credshield_agent_issues_total[1m]))*60", "{{result}}")], 0, 8,
      desc="Попытки получить учётные данные: успешные и с ошибкой")
panel("Задержка выдачи (вход и получение данных)",
      [("histogram_quantile(0.5, sum by (le) (rate(credshield_agent_issue_duration_seconds_bucket[1m])))", "p50"),
       ("histogram_quantile(0.99, sum by (le) (rate(credshield_agent_issue_duration_seconds_bucket[1m])))", "p99")],
      12, 8, unit="s")
panel("События агента: повторы, замены, удаление файла",
      [('sum by (event) (increase(credshield_agent_events_total{event=~"retry|replaced|expiring_soon|expired_removed"}[1m]))',
        "{{event}}")], 0, 16, desc="Число событий за минуту")
panel("Запросы микросервисов к СУБД, в секунду",
      [("sum by (service, result) (rate(credshield_app_queries_total[30s]))", "{{service}} / {{result}}")], 12, 16)
panel("Обращения по журналу аудита, в минуту",
      [("sum by (role, result) (rate(credshield_responder_events_total[1m]))*60", "{{role}} / {{result}}")], 0, 24,
      desc="Разрешённые и отклонённые обращения к учётным данным")
panel("Решения детектора и отзывы",
      [("sum by (reason) (credshield_responder_decisions_total)", "решение: {{reason}}"),
       ("sum by (result) (credshield_responder_revocations_total)", "отзыв: {{result}}")], 12, 24,
      desc="Накопленные значения счётчиков")
panel("CPU контейнеров, ядер",
      [('sum by (container) (rate(container_cpu_usage_seconds_total{namespace="credshield",container!="",container!="POD"}[30s]))',
        "{{container}}")], 0, 32)
panel("Память контейнеров (working set)",
      [('sum by (container) (container_memory_working_set_bytes{namespace="credshield",container!="",container!="POD"})',
        "{{container}}")], 12, 32, unit="bytes")
panel("Перезапуски контейнеров за 5 минут",
      [('sum by (container) (changes(container_start_time_seconds{namespace="credshield",container!="",container!="POD"}[5m]))',
        "{{container}}")], 0, 40, w=12, desc="Изменения времени запуска контейнера — признак перезапуска")
panel("Активные оповещения", [('ALERTS{alertstate="firing"}', "{{alertname}} ({{severity}})")], 12, 40, w=12,
      desc="Правила Prometheus: замена не удаётся, срок на исходе, отзыв и др.")

panel("Нагрузочный замер: запросов в секунду",
      [("sum by (result) (rate(credshield_bench_requests_total[10s]))", "{{result}}"),
       ("max(credshield_bench_target_rate)", "задано")], 0, 48, desc="Выдачи учётных данных клиентом нагрузки")
panel("Нагрузочный замер: задержка запроса",
      [("histogram_quantile(0.5, sum by (le) (rate(credshield_bench_duration_seconds_bucket[15s])))", "p50"),
       ("histogram_quantile(0.95, sum by (le) (rate(credshield_bench_duration_seconds_bucket[15s])))", "p95"),
       ("histogram_quantile(0.99, sum by (le) (rate(credshield_bench_duration_seconds_bucket[15s])))", "p99")],
      12, 48, unit="s")

dash = {"uid": "credshield", "title": "Выдача учётных данных: состояние подсистемы", "schemaVersion": 39, "version": 1,
        "refresh": "5s", "time": {"from": "now-15m", "to": "now"}, "timezone": "browser", "editable": True,
        "panels": panels, "templating": {"list": []}, "tags": ["credshield"]}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "chart", "files", "dashboard.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(dash, f, ensure_ascii=False, indent=1)
print(out, len(panels), "панелей")

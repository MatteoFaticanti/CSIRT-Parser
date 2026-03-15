import dash_mantine_components as dmc
from dash import Dash, Input, Output, callback, dcc
import pandas as pd, sqlite3, json
import plotly.express as px
from database import DB_PATH

app = Dash(__name__, external_stylesheets=dmc.styles.ALL)

def carica_dati():
    df = pd.read_sql_query("SELECT * FROM bollettini", sqlite3.connect(DB_PATH))
    df['cvss'] = df['cvss'].fillna(0.0)
    df['cve_correlate'] = df['cve_correlate'].apply(
        lambda s: ", ".join(json.loads(s)) if s else ""
    )
    return df

df = carica_dati()

def kpi_card(label, value, color, icon):
    return dmc.Paper(
        dmc.Group([
            dmc.ThemeIcon(dmc.Text(icon, size="xl"), size=54, radius="md", color=color, variant="light"),
            dmc.Stack([
                dmc.Text(label, size="sm", c="dimmed", tt="uppercase", fw=600, style={"letterSpacing": 1}),
                dmc.Text(str(value), size="xl", fw=800, c=color),
            ], gap=2),
        ], align="center"),
        p="lg", radius="md", withBorder=True, shadow="sm",
        style={"flex": 1, "background": "#1a1b2e", "borderColor": "#2d2e4a"},
    )

# In DMC 2.x: navbar/header sono dict di config, i componenti vanno in children
app.layout = dmc.MantineProvider(
    forceColorScheme="dark",
    children=dmc.AppShell(
        [
            dmc.AppShellHeader(
                dmc.Group([
                    dmc.Text("🛡️", size="xl"),
                    dmc.Title("CSIRT Italia Parser", order=3, c="white"),
                ], h="100%", px="lg"),
                style={"background": "#0f0f1a", "borderBottom": "1px solid #2d2e4a"},
            ),
            dmc.AppShellNavbar(
                dmc.Stack([
                    dmc.Title("Filtri", order=5, c="dimmed"),
                    dmc.Divider(),
                    dmc.TextInput(id="cerca-cve", placeholder="Cerca CVE...", label="CVE"),
                    dmc.Text("CVSS Minimo", size="sm", c="dimmed"),
                    dmc.Slider(id="cvss-min", min=0, max=10, step=0.1, value=0, marks=[
                        {"value": 0, "label": "0"}, {"value": 4, "label": "4"},
                        {"value": 7, "label": "7"}, {"value": 9, "label": "9"},
                    ], color="blue", mb="md"),
                    dmc.MultiSelect(id="tech-filter", label="Tecnologia",
                                    data=sorted(df['tecnologia'].unique().tolist()),
                                    searchable=True, clearable=True),
                    dmc.Switch(id="solo-exploited", label="🔥 Solo Exploited", color="orange"),
                    dmc.Switch(id="solo-poc",       label="🧪 Solo con PoC",   color="grape"),
                ], p="md", gap="sm"),
                style={"background": "#12121f", "borderRight": "1px solid #2d2e4a"},
            ),
            dmc.AppShellMain(
                dmc.Stack([
                    dmc.Group(id="kpi-row", grow=True),
                    dmc.Divider(),
                    dmc.SimpleGrid(id="grafici", cols=2),
                    dmc.Divider(),
                    dmc.Paper([
                        dmc.Text("Dettaglio Bollettini", size="sm", c="dimmed", tt="uppercase", fw=600, style={"letterSpacing": 1}, mb="sm"),
                        dmc.Box(id="tabella"),
                    ], p="lg", radius="md", withBorder=True,
                       style={"background": "#1a1b2e", "borderColor": "#2d2e4a"}),
                ], p="lg", gap="lg"),
                style={"background": "#0d0d1a"},
            ),
        ],
        header={"height": 56},
        navbar={"width": 280, "breakpoint": "sm"},
        padding=0,
    )
)

@callback(
    Output("kpi-row", "children"),
    Output("grafici",  "children"),
    Output("tabella",  "children"),
    Input("cerca-cve",      "value"),
    Input("cvss-min",       "value"),
    Input("tech-filter",    "value"),
    Input("solo-exploited", "checked"),
    Input("solo-poc",       "checked"),
)
def aggiorna(cerca, cvss, tech, exp, poc):
    d = df[df['cvss'] >= (cvss or 0)]
    if cerca: d = d[d['cve_correlate'].str.contains(cerca, case=False, na=False)]
    if tech:  d = d[d['tecnologia'].isin(tech)]
    if exp:   d = d[d['is_exploited'] == 1]
    if poc:   d = d[d['has_poc'] == 1]

    media = round(d.cvss.mean(), 1) if len(d) else 0.0

    kpis = [
        kpi_card("Bollettini", len(d),                     "blue",   "📋"),
        kpi_card("Critici",    len(d[d.cvss >= 9]),         "red",    "🚨"),
        kpi_card("Exploited",  int(d.is_exploited.sum()),   "orange", "🔥"),
        kpi_card("Media CVSS", media,
                 "red" if media >= 9 else "orange" if media >= 7 else "blue", "📊"),
    ]

    _dark = {"plot_bgcolor": "#1a1b2e", "paper_bgcolor": "#1a1b2e", "font": {"color": "#ccc"}}
    fig_bar = px.bar(d['tecnologia'].value_counts().head(10).reset_index(),
                     x='count', y='tecnologia', orientation='h',
                     title="Top Tecnologie Colpite", template="plotly_dark")
    fig_pie = px.pie(d['tipologia_attacco'].value_counts().reset_index(),
                     values='count', names='tipologia_attacco',
                     hole=0.4, title="Tipologia Attacco", template="plotly_dark")
    fig_bar.update_layout(**_dark)
    fig_pie.update_layout(**_dark, uniformtext_minsize=10, uniformtext_mode="hide",
                          margin={"t": 40, "b": 40, "l": 40, "r": 40})
    fig_pie.update_traces(textposition="inside", textinfo="percent",
                          insidetextorientation="radial")

    d_show = (d[['data_pubblicazione','titolo','cvss','cve_correlate',
                 'tecnologia','tipologia_attacco','is_exploited','has_poc','url']]
              .sort_values("data_pubblicazione", ascending=False))

    rows = [
        dmc.TableTr([
            dmc.TableTd(str(r.data_pubblicazione)[:10],
                        style={"color": "#868e96", "fontSize": 12}),
            dmc.TableTd(r.titolo,
                        style={"maxWidth": 300, "overflow": "hidden",
                               "textOverflow": "ellipsis", "whiteSpace": "nowrap"}),
            dmc.TableTd(dmc.Badge(
                f"{r.cvss:.1f}",
                color="red" if r.cvss >= 9 else "orange" if r.cvss >= 7 else "blue",
                variant="light",
            )),
            dmc.TableTd(r.cve_correlate,
                        style={"maxWidth": 280, "overflow": "hidden",
                               "textOverflow": "ellipsis", "whiteSpace": "nowrap",
                               "fontSize": 12}),
            dmc.TableTd(r.tecnologia,        style={"fontSize": 12}),
            dmc.TableTd(r.tipologia_attacco, style={"fontSize": 12}),
            dmc.TableTd(dmc.Badge("✓", color="orange", variant="dot") if r.is_exploited else ""),
            dmc.TableTd(dmc.Badge("✓", color="grape",  variant="dot") if r.has_poc else ""),
            dmc.TableTd(dmc.Anchor("Apri", href=r.url, target="_blank", size="sm")),
        ])
        for r in d_show.itertuples()
    ]

    tabella = dmc.ScrollArea(
        dmc.Table(
            [
                dmc.TableThead(dmc.TableTr([
                    dmc.TableTh(c) for c in
                    ["Data", "Titolo", "CVSS", "CVE", "Tecnologia", "Tipologia", "Expl.", "PoC", "Link"]
                ])),
                dmc.TableTbody(rows),
            ],
            striped=True, highlightOnHover=True,
            style={"fontSize": 13, "width": "100%", "tableLayout": "fixed"},
        ),
        h=500,
        style={"width": "100%"},
    )

    graph_config = {"displayModeBar": False}
    return kpis, [
        dcc.Graph(figure=fig_bar, config=graph_config),
        dcc.Graph(figure=fig_pie, config=graph_config),
    ], tabella


if __name__ == "__main__":
    app.run(debug=False)

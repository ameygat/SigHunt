import dash
from dash import html, Input, Output, callback
import dash_mantine_components as dmc
from utils.db import User
dash.register_page(__name__, path="/leaderboard", title="Leaderboard")
def layout():
    return html.Div(id="lb-content")
@callback(Output("lb-content","children"), Input("url","pathname"))
def render(pathname):
    players = User.query.filter_by(role="player").order_by(User.score.desc()).limit(50).all()
    medals = {1:"🥇",2:"🥈",3:"🥉"}
    rows = [dmc.TableTr([dmc.TableTd(f"{medals.get(i," ")} {str(i)}"), dmc.TableTd(u.username), dmc.TableTd(str(u.score))])
            for i,u in enumerate(players,1)]
    return dmc.Stack(gap="lg", children=[
        dmc.Title("🏆 Leaderboard", order=2),
        dmc.Paper(p="md", radius="md", withBorder=True, children=dmc.Table(
            withTableBorder=True, striped=True, highlightOnHover=True,
            children=[
                dmc.TableThead(dmc.TableTr([dmc.TableTh("Rank"),dmc.TableTh("Player"),dmc.TableTh("Score")])),
                dmc.TableTbody(rows or [dmc.TableTr([dmc.TableTd("No players yet.",attributes={"colspan": "3"})])]),
            ]
        )),
    ])

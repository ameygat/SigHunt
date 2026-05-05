import dash
from dash import html, Input, Output, callback
import dash_mantine_components as dmc
import dash_iconify
from utils.db import Challenge, Submission
dash.register_page(__name__, path="/challenges", title="Challenges")
DIFF = {"easy":"green","medium":"yellow","hard":"orange","expert":"red"}
def layout():
    return html.Div(id="chal-content")
@callback(Output("chal-content","children"), Input("auth-store","data"))
def render(auth_data):
    a = auth_data or {}
    if not a.get("logged_in"):
        return dmc.Alert("Please log in to view challenges.", color="yellow",
                         icon=dash_iconify.DashIconify(icon="tabler:lock",width=20))
    uid = a["user_id"]
    chals = Challenge.query.filter_by(status="published").order_by(Challenge.points).all()
    solved_ids = {s.challenge_id for s in Submission.query.filter_by(user_id=uid,is_correct=True).all()}
    if not chals:
        return dmc.Stack([dmc.Title("Challenges",order=2),dmc.Alert("No challenges yet.",color="blue")])
    cards = []
    for ch in chals:
        solved = ch.id in solved_ids
        cards.append(dmc.Paper(p="md",radius="md",withBorder=True,
            style={"opacity":"0.65" if solved else "1"},
            children=dmc.Stack(gap="xs",children=[
                dmc.Group(justify="space-between",children=[
                    dmc.Text(ch.title,fw=600),
                    dmc.Badge("✓ Solved" if solved else ch.difficulty.upper(),
                              color="green" if solved else DIFF.get(ch.difficulty,"gray"),variant="light"),
                ]),
                dmc.Group(gap="xs",children=[
                    dmc.Badge(ch.category,variant="dot"),
                    dmc.Badge(f"{ch.points} pts",color="blue",variant="outline"),
                ]),
                dmc.Text((ch.description[:110]+"…") if len(ch.description)>110 else ch.description,
                         size="sm",c="dimmed"),
                dmc.Anchor(dmc.Button("View Challenge",variant="subtle",size="xs",disabled=solved),
                           href=f"/challenge/{ch.id}"),
            ])))
    return dmc.Stack(gap="lg",children=[
        dmc.Title("Challenges",order=2),
        dmc.SimpleGrid(cols={"base":1,"sm":2,"lg":3},spacing="md",children=cards),
    ])

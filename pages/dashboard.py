import dash
from dash import html, Input, Output, callback
import dash_mantine_components as dmc
import dash_iconify
from utils.db import db, User, Challenge, Submission
dash.register_page(__name__, path="/dashboard", title="Dashboard")
def layout():
    return html.Div(id="dash-content")
@callback(Output("dash-content","children"), Input("auth-store","data"))
def render(auth_data):
    a = auth_data or {}
    if not a.get("logged_in"):
        return dmc.Alert("Please log in.", color="red")
    user = User.query.get(a["user_id"])
    if not user:
        return dmc.Alert("User not found.", color="red")
    total = Challenge.query.filter_by(status="published").count()
    solved = Submission.query.filter_by(user_id=user.id, is_correct=True).count()
    players = User.query.filter_by(role="player").count()
    row = db.session.execute(
        db.text("SELECT COUNT(*)+1 FROM users WHERE score>:s AND role='player'"),
        {"s":user.score}).fetchone()
    rank = row[0] if row else "?"
    subs = Submission.query.filter_by(user_id=user.id,is_correct=True).order_by(Submission.submitted_at.desc()).limit(5).all()
    rows = []
    for s in subs:
        ch = Challenge.query.get(s.challenge_id)
        if ch:
            rows.append(dmc.TableTr([dmc.TableTd(ch.title),dmc.TableTd(ch.category),
                                     dmc.TableTd(str(ch.points)),dmc.TableTd(str(s.submitted_at)[:16])]))
    def card(label,val,icon,color):
        return dmc.Paper(p="md",radius="md",withBorder=True,children=dmc.Group(gap="md",children=[
            dmc.ThemeIcon(dash_iconify.DashIconify(icon=icon,width=24),size="lg",color=color,variant="light"),
            dmc.Stack(gap=0,children=[dmc.Text(val,fw=700,size="xl"),dmc.Text(label,c="dimmed",size="sm")]),
        ]))
    return dmc.Stack(gap="lg",children=[
        dmc.Title(f"Welcome, {user.username}!", order=2),
        dmc.SimpleGrid(cols={"base":1,"sm":2,"lg":4},spacing="md",children=[
            card("Score",str(user.score),"tabler:star","yellow"),
            card("Rank",f"#{rank}","tabler:trophy","orange"),
            card("Solved",f"{solved}/{total}","tabler:flag","teal"),
            card("Players",str(players),"tabler:users","blue"),
        ]),
        dmc.Paper(p="md",radius="md",withBorder=True,children=[
            dmc.Title("Recent Solves",order=4,mb="sm"),
            dmc.Table(withTableBorder=True,striped=True,highlightOnHover=True,children=[
                dmc.TableThead(dmc.TableTr([dmc.TableTh("Challenge"),dmc.TableTh("Category"),dmc.TableTh("Points"),dmc.TableTh("At")])),
                dmc.TableTbody(rows or [dmc.TableTr([dmc.TableTd("No solves yet.",attributes={"colspan": "4"})])]),
            ]),
        ]),
    ])

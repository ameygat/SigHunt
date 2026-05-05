import os
import dash
import dash_mantine_components as dmc
import dash_iconify
from dash import html, dcc, Input, Output, State, callback
from flask import Flask
from flask_login import logout_user
from utils.db import db
from utils.auth import login_manager, seed_admin
import dash_ag_grid as dag
import dash_ace
server = Flask(__name__)
server.secret_key = os.environ.get("SECRET_KEY", "ctf-dev-secret-change-in-prod-143")
server.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://ctf_user:ctf_password@localhost/ctf_platform"
)
server.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
server.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

db.init_app(server)
login_manager.init_app(server)

app = dash.Dash(
    __name__,
    server=server,
    use_pages=True,
    suppress_callback_exceptions=True,
)

app.layout = dmc.MantineProvider(
    forceColorScheme="dark",
    children=[
        #dcc.Location(id="url", refresh=False), #gives error does not refresh page after login or logout etc
        #so replaced by following callback-nav
        dcc.Location(id="url", refresh="callback-nav"),
        dcc.Store(id="auth-store", storage_type="session", data={}),
        html.Div(id="navbar-container"),
        dmc.Container(dash.page_container, size="xl", pt="md", pb="xl"),
    ],
)


@callback(
    Output("navbar-container", "children"),
    Input("url", "pathname"),
    Input("auth-store", "data"),
)
def render_navbar(pathname, auth_data):
    auth_data = auth_data or {}
    logged_in = auth_data.get("logged_in", False)
    is_admin  = auth_data.get("role") == "admin"
    username  = auth_data.get("username", "")

    if logged_in:
        nav_links = [
            dmc.Anchor("Dashboard",   href="/dashboard",  c="dimmed", underline="never"),
            dmc.Anchor("Challenges",  href="/challenges", c="dimmed", underline="never"),
            dmc.Anchor("Leaderboard", href="/leaderboard",c="dimmed", underline="never"),
        ]
        if is_admin:
            nav_links += [
                dmc.Anchor("Create Challenge", href="/admin/create",  c="yellow", underline="never"),
                dmc.Anchor("Manage",           href="/admin/manage",  c="yellow", underline="never"),
            ]
        right = dmc.Group(gap="md", children=[
            *nav_links,
            dmc.Menu(children=[
                dmc.MenuTarget(dmc.Button(
                    username, variant="subtle", size="sm",
                    rightSection=dash_iconify.DashIconify(icon="tabler:chevron-down", width=14),
                )),
                dmc.MenuDropdown([
                    dmc.MenuItem("Profile",         href="/profile",         leftSection=dash_iconify.DashIconify(icon="tabler:user",   width=14)),
                    dmc.MenuItem("Change Password", href="/change-password", leftSection=dash_iconify.DashIconify(icon="tabler:lock",   width=14)),
                    dmc.MenuDivider(),
                    dmc.MenuItem("Logout", id="logout-btn", c="red",         leftSection=dash_iconify.DashIconify(icon="tabler:logout", width=14)),
                ]),
            ]),
        ])
    else:
        right = dmc.Group(gap="sm", children=[
            dmc.Anchor("Leaderboard", href="/leaderboard", c="dimmed", underline="never"),
            dmc.Anchor(dmc.Button("Login",    variant="subtle", size="sm"), href="/login"),
            dmc.Anchor(dmc.Button("Register", variant="filled", size="sm"), href="/register"),
        ])

    return dmc.Paper(
        withBorder=True,
        radius=0,
        p="md",
        mb="xs",
        children=dmc.Group(
            justify="space-between",
            children=[
                dmc.Anchor(
                    #dmc.Text("🏴 SigHunt", fw=700, size="lg"),
                    dmc.Image(src="assets/sigma_new1.png",h=70,w="auto"),
                    href="/", underline="never",
                ),
                dmc.Text("The Sigma rule CTF", fw=700, size="xl"),
                dmc.Space(),
                dmc.Space(),
                dmc.Space(),
                right,
            ],
        ),
    )


@callback(
    Output("url", "pathname",   allow_duplicate=True),
    Output("auth-store", "data", allow_duplicate=True),
    Input("logout-btn", "n_clicks"),
    prevent_initial_call=True,
)
def do_logout(n):
    if n:
        logout_user()
        return "/login", {}
    return dash.no_update, dash.no_update


if __name__ == "__main__":
    with server.app_context():
        db.create_all()
        seed_admin(server)
    app.run(debug=False, host="0.0.0.0", port=8050)

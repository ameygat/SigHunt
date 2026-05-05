import dash
import dash_mantine_components as dmc
import dash_iconify
dash.register_page(__name__, path="/", title="SigHunt CTF")
def layout():
    return dmc.Stack(gap="xl", align="center", pt="xl", children=[
        dmc.Title("⚐ SigHunt", order=1, ta="center"),
        dmc.Text("A CTF platform to sharpen Sigma rule detection skills.",
                 ta="center", c="dimmed", size="lg"),
        dmc.Group(justify="center", gap="md", children=[
            dmc.Anchor(dmc.Button("Play Challenges", size="lg",
                leftSection=dash_iconify.DashIconify(icon="tabler:shield",  width=20)),
                href="/challenges"),
            dmc.Anchor(dmc.Button("Leaderboard", size="lg", variant="outline",
                leftSection=dash_iconify.DashIconify(icon="tabler:trophy", width=20)),
                href="/leaderboard"),
        ]),
    ])

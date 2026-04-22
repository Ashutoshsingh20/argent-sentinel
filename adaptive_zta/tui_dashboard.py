import pandas as pd
import os
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import Header, Footer, Static, DataTable, Sparkline
from textual.binding import Binding
from textual.reactive import reactive
import database as db
from sqlalchemy import func

class MetricWidget(Static):
    pass

class AdaptiveZTADashboard(App):
    TITLE = "Vanguard V3 Production Command Center"
    CSS = """
    Screen {
        background: #090B10;
        color: #F0F6FC;
    }
    #sidebar {
        width: 25%;
        border-right: solid #00f0ff;
        padding: 1 1;
        background: #12161d;
    }
    #main-content {
        width: 45%;
        padding: 1 1;
    }
    #forensics-panel {
        width: 30%;
        border-left: solid #7000FF;
        padding: 1 1;
        background: #0D1117;
    }
    MetricWidget {
        padding: 0 1;
        margin: 0 0 1 0;
        border: round #484F58;
        height: 4;
        content-align: center middle;
    }
    Sparkline {
        width: 100%;
        height: 1;
        margin-bottom: 1;
        color: #00f0ff;
    }
    .trend-label {
        color: #8B949E;
        margin-bottom: 0;
    }
    #table-title {
        text-align: center;
        padding-bottom: 1;
        color: #00f0ff;
        text-style: bold;
    }
    .forensic-title {
        color: #7000FF;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    .forensic-sub {
        color: #8B949E;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit Dashboard"),
        Binding("r", "refresh_data", "Force Refresh"),
    ]

    selected_entity = reactive("")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield MetricWidget("", id="metric-entities")
                yield Static("Avg Trust Health", classes="trend-label")
                yield Sparkline(id="spark-trust")
                
                yield MetricWidget("", id="metric-allow")
                yield Static("Allowance Volume", classes="trend-label")
                yield Sparkline(id="spark-allow")
                
                yield MetricWidget("", id="metric-isolate")
                yield Static("Active Isolation", classes="trend-label")
                yield Sparkline(id="spark-isolate")
                
            with Vertical(id="main-content"):
                yield Static("### PRODUCTION THREAT MATRIX (DB-LIVE) ###", id="table-title")
                yield DataTable(id="escaped-table")
            
            with Vertical(id="forensics-panel"):
                yield Static("--- FORENSIC DEEP-DIVE ---", classes="forensic-title")
                yield Static("Select a record from the matrix for real-time trace.", id="forensic-hint")
                yield Container(id="forensic-content")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#escaped-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Entity ID", "Status", "Trust Score", "Last Event")
        
        self.load_from_db()
        self.set_interval(2.0, self.load_from_db)

    def load_from_db(self) -> None:
        session = db.SessionLocal()
        try:
            # 1. Global Metrics
            ent_count = session.query(db.Entity).count()
            allow_count = session.query(db.Entity).filter(db.Entity.status == "ALLOW").count()
            iso_count = session.query(db.Entity).filter(db.Entity.status == "ISOLATE").count()
            
            self.query_one("#metric-entities", MetricWidget).update(f"Managed Entities\n[b][#00f0ff]{ent_count}[/][/]")
            self.query_one("#metric-allow", MetricWidget).update(f"ALLOW\n[b][#00E676]{allow_count}[/][/]")
            self.query_one("#metric-isolate", MetricWidget).update(f"ISOLATE\n[b][#FF2A2A]{iso_count}[/][/]")
            
            # 2. Sparklines (Aggregated Trust Trend)
            avg_trusts = session.query(func.avg(db.Telemetry.api_rate)).group_by(db.Telemetry.timestep).order_by(db.Telemetry.timestep.desc()).limit(50).all()
            if avg_trusts:
                self.query_one("#spark-trust", Sparkline).data = [float(x[0]) for x in reversed(avg_trusts)]

            # 3. Active Threat Table (Most recent isolation actions)
            threats = (
                session.query(db.EnforcementAction)
                .order_by(
                    (db.EnforcementAction.decision == "ISOLATE").desc(),
                    db.EnforcementAction.timestamp.desc(),
                )
                .limit(20)
                .all()
            )
            table = self.query_one("#escaped-table", DataTable)
            table.clear()
            for action in threats:
                ts = f"{action.trust_score_at_action:.2f}"
                status_markup = f"[b][#FF2A2A]{action.decision}[/][/]" if action.decision == "ISOLATE" else f"[#00E676]{action.decision}[/]"
                table.add_row(action.entity_id, status_markup, ts, action.timestamp.strftime("%H:%M:%S"))

            if self.selected_entity:
                self.update_forensic_panel(self.selected_entity)
        except Exception as e:
            self.notify(f"DB Load Error: {str(e)}", severity="error")
        finally:
            session.close()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#escaped-table", DataTable)
        row_data = table.get_row(event.row_key)
        self.selected_entity = row_data[0]
        self.update_forensic_panel(self.selected_entity)

    def update_forensic_panel(self, entity_id: str) -> None:
        session = db.SessionLocal()
        try:
            entity = session.query(db.Entity).filter(db.Entity.id == entity_id).first()
            if not entity: return
            
            content = self.query_one("#forensic-content", Container)
            content.remove_children()
            
            content.mount(Static(f"\n[b]PRO-ID:[/][#8B949E] {entity.id}[/]"))
            content.mount(Static(f"[b]Infrastructure:[/][#8B949E] {entity.cloud_env} / {entity.entity_type}[/]"))
            content.mount(Static(f"[b]Current Trust:[/][#8B949E] {entity.current_trust_score:.2f}[/]"))
            
            # Latest Enforcement Reason
            latest_action = session.query(db.EnforcementAction).filter(db.EnforcementAction.entity_id == entity_id).order_by(db.EnforcementAction.timestamp.desc()).first()
            if latest_action:
                content.mount(Static(f"\n[b]Enforcement Reason:[/]\n{latest_action.reason}", classes="forensic-sub"))
            
            # History Sparkline (Last 50 events)
            history = session.query(db.Telemetry.api_rate).filter(db.Telemetry.entity_id == entity_id).order_by(db.Telemetry.timestep.desc()).limit(50).all()
            if history:
                content.mount(Static("\nBehavioral Flux:", classes="trend-label"))
                content.mount(Sparkline(data=[float(x[0]) for x in reversed(history)]))
            
            self.query_one("#forensic-hint").display = False
        finally:
            session.close()

if __name__ == "__main__":
    app = AdaptiveZTADashboard()
    app.run()

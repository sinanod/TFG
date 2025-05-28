from flask import Flask, render_template, make_response
from dash import Dash, dcc, html, State, Output, Input, callback
import plotly.express as px
import pandas as pd
from fpdf import FPDF
from security_evaluator import generate_security_report

app = Flask(__name__)
dash_app = Dash(__name__, server=app, url_base_pathname='/dashboard/')

# --------------------------
# Cargar datos de auditoría
# --------------------------
report_data = generate_security_report()
resources = report_data['resources']
checks = report_data['checks']

# --------------------------
# Dashboard Interactivo
# --------------------------
# Preparar DataFrame de VMs
vms = resources['vms']
if vms:
    df_vms = pd.DataFrame({
        'Nombre_VM': [vm['name'] for vm in vms],
        'Cifrado_Disco': [
            'Sí' if 'Sin cifrado' not in vm['disk_encryption'][0] else 'No'
            for vm in vms
        ],
        'Diagnóstico_Boot': [
            'Habilitado' if 'Deshabilitados' not in vm['boot_diagnostics'] else 'Deshabilitado'
            for vm in vms
        ],
    })
else:
    df_vms = pd.DataFrame(columns=['Nombre_VM', 'Cifrado_Disco', 'Diagnóstico_Boot'])

fig_cifrado_discos = px.bar(
    df_vms,
    x='Nombre_VM',
    y='Cifrado_Disco',
    title='Estado de Cifrado de Discos en VMs'
)

fig_diagnostics = px.pie(
    df_vms,
    names='Diagnóstico_Boot',
    title='Diagnósticos de Arranque (VMs)'
)


# Layout del Dashboard
# Crear gráficos dinámicos con los datos ya cargados
def get_dashboard_layout():
    layout_components = []

    # Crear gráfico resumen de checks
    all_checks = []
    for check_list in checks.values():
        all_checks.extend(check_list)
    df_checks = pd.DataFrame(all_checks)

    passed = df_checks['passed'].sum()
    failed = len(df_checks) - passed
    fig_resumen = px.pie(values=[passed, failed], names=['Aprobados', 'Fallidos'], title='Resumen de Checks')

    fig_resumen.update_layout(
        legend=dict(
            font=dict(size=16),
            title_font=dict(size=16)
        )
    )

    layout_components.append(html.Div([
        html.H1("Dashboard de Seguridad de Azure", className="main-title"),
        dcc.Graph(figure=fig_resumen, className="card")
    ], className="content-wrapper"))

    # VMs
    if resources['vms']:
        df_vms = pd.DataFrame({
            'VM': [vm['name'] for vm in resources['vms']],
            'Cifrado': ['Sí' if 'Sin cifrado' not in vm['disk_encryption'][0] else 'No' for vm in resources['vms']],
            'Diagnóstico': ['Habilitado' if 'Deshabilitados' not in vm['boot_diagnostics'] else 'Deshabilitado'
                            for vm in resources['vms']]
        })
        fig_vm_cifrado = px.histogram(df_vms, x='VM', color='Cifrado', title='Cifrado de discos (VMs)')
        fig_vm_diag = px.pie(df_vms, names='Diagnóstico', title='Diagnóstico de arranque (VMs)')
        fig_vm_diag.update_layout(
            legend=dict(
                font=dict(size=16),
                title_font=dict(size=16)
            )
        )
        fig_vm_cifrado.update_layout(
            legend=dict(
                font=dict(size=16),
                title_font=dict(size=16)
            )
        )

        layout_components.append(html.Div([
            html.H3("Máquinas Virtuales", id="vms"),
            html.Div([
                dcc.Graph(figure=fig_vm_cifrado, className="card"),
                dcc.Graph(figure=fig_vm_diag, className="card")
            ], className="row-2")
        ], className="content-wrapper"))

    # SQL Servers
    fig_sql = None

    sql_checks = checks.get('sql', [])
    if sql_checks:
        sql_summary = pd.DataFrame([
            {'SQL': c['resource'], 'Check': c['name'], 'Estado': 'Fallido' if not c['passed'] else 'Aprobado'}
            for c in sql_checks if 'sql' in c['name']
        ])
        if not sql_summary.empty:
            fig_sql = px.histogram(sql_summary, x='SQL', color='Estado', title='Checks en SQL Servers')
            fig_sql.update_layout(
                legend=dict(
                    font=dict(size=16),
                    title_font=dict(size=16)
                )
            )

            layout_components.append(html.Div([
                html.H3("SQL Servers", id="sql"),
                dcc.Graph(figure=fig_sql, className="card")
            ], className="content-wrapper") if fig_sql else None,
                                     )

    # Storage
    storage_data = resources.get('storage_accounts', [])
    if storage_data:
        df_storage = pd.DataFrame(storage_data)
        fig_storage_encrypt = px.pie(df_storage, names='encryption', title='Cifrado en Storage Accounts')
        fig_storage_public = px.pie(
            df_storage,
            names=df_storage['public_access'].map({True: 'Público', False: 'Privado'}),
            title='Acceso público en Storage Accounts'
        )
        fig_storage_encrypt.update_layout(
            legend=dict(
                font=dict(size=16),
                title_font=dict(size=16)
            )
        )
        fig_storage_public.update_layout(
            legend=dict(
                font=dict(size=16),
                title_font=dict(size=16)
            )
        )

        layout_components.append(html.Div([
            html.H3("Storage Accounts", id="storage"),
            html.Div([
                dcc.Graph(figure=fig_storage_encrypt, className="card"),
                dcc.Graph(figure=fig_storage_public, className="card")
            ], className="row-2")
        ], className="content-wrapper"))

    # IAM
    iam_data = resources.get('iam', [])
    if iam_data:
        df_iam = pd.DataFrame(iam_data)
        fig_iam_roles = px.histogram(df_iam, x='role', title='Distribución de Roles IAM', labels={'role': 'Rol'})
        fig_iam_roles.update_layout(
            legend=dict(
                font=dict(size=16),
                title_font=dict(size=16)
            )
        )

        layout_components.append(html.Div([
            html.H3("IAM (Identidad y Acceso)", id="iam"),
            dcc.Graph(figure=fig_iam_roles, className="card")
        ], className="content-wrapper"))

    # Críticidad Global
    if 'criticality' in df_checks.columns:
        fig_criticidad = px.histogram(
            df_checks,
            x='criticality',
            color='passed',
            barmode='group',
            title='Resumen por Criticidad',
            labels={'criticality': 'Criticidad', 'passed': 'Estado'}
        )
        fig_criticidad.update_layout(
            legend=dict(
                font=dict(size=16),
                title_font=dict(size=16)
            )
        )
        layout_components.append(html.Div([
            html.H3("Resumen por Criticidad"),
            dcc.Graph(figure=fig_criticidad, className="card")
        ], className="content-wrapper"))

    return html.Div([
        dcc.Location(id="url", refresh=False),
        dcc.Store(id="sidebar-state", data={"collapsed": False}),

        # SIDEBAR
        html.Div([
            html.Img(
                src="./assets/images/URJC_logo.png",
                className="sidebar-logo logo-expandido"),
            html.Img(
                src="./assets/images/Logo_URJC.png",
                className="sidebar-logo logo-colapsado"),

            html.Ul([
                html.Li([
                    html.Span("📊", className="nav-icon"),
                    html.A("Dashboard", href="#dashboard", className="nav-link")
                ]),
                html.Li([
                    html.Span("🖥️", className="nav-icon"),
                    html.A("VMs", href="#vms", className="nav-link")
                ]),
                html.Li([
                    html.Span("🗄️", className="nav-icon"),
                    html.A("SQL", href="#sql", className="nav-link")
                ]),
                html.Li([
                    html.Span("💾", className="nav-icon"),
                    html.A("Storage", href="#storage", className="nav-link")
                ]),
                html.Li([
                    html.Span("🔐", className="nav-icon"),
                    html.A("IAM", href="#iam", className="nav-link")
                ]),
            ], className="sidebar-menu")
        ], id="sidebar", className="sidebar"),

        # MAIN CONTENT
        html.Div([
            # TOPBAR
            html.Div([
                html.Button("☰", className="menu-toggle", id="toggle-button"),

                html.Div("Bienvenido, Sinan", className="topbar-text"),
                html.Img(
                    src="https://media.licdn.com/dms/image/v2/D4D03AQFDCaDxIFMwFQ/profile-displayphoto-shrink_200_200/profile-displayphoto-shrink_200_200/0/1693912781393?e=2147483647&v=beta&t=bYxjAljXG0Y-0R9yRPxuaSQVuujPolTXiXjqYykKtuQ",
                    className="avatar")
            ], className="topbar"),

            html.Div([
                html.H1("Dashboard de Seguridad de Azure", className="main-title", id="dashboard"),

                html.Div([dcc.Graph(figure=fig_resumen, className="card")], className="grid-1"),

                html.Div([
                    html.H3("Máquinas Virtuales", id="vms"),
                    html.Div([
                        dcc.Graph(figure=fig_vm_cifrado, className="card"),
                        dcc.Graph(figure=fig_vm_diag, className="card")
                    ], className="row-2")
                ], className="content-wrapper"),

                html.Div([
                    html.H3("SQL Servers", id="sql"),
                    dcc.Graph(figure=fig_sql, className="card")
                ], className="content-wrapper") if 'sql' in checks else None,

                html.Div([
                    html.H3("Storage Accounts", id="storage"),
                    html.Div([
                        dcc.Graph(figure=fig_storage_encrypt, className="card"),
                        dcc.Graph(figure=fig_storage_public, className="card")
                    ], className="row-2")
                ], className="content-wrapper") if 'storage_accounts' in resources else None,

                html.Div([
                    html.H3("IAM", id="iam"),
                    dcc.Graph(figure=fig_iam_roles, className="card")
                ], className="content-wrapper") if 'iam' in resources else None,

                html.Div([
                    html.H3("Resumen por Criticidad"),
                    dcc.Graph(figure=fig_criticidad, className="card")
                ], className="content-wrapper") if 'criticality' in df_checks.columns else None
            ], className="main-content")
        ], className="page-content")

    ], className="app-layout")


# Asignar layout
dash_app.layout = get_dashboard_layout()


# --------------------------
# Rutas de Flask
# --------------------------
@app.route('/')
def index():
    return render_template('index.html', resources=resources, checks=checks)


@app.route('/download_report')
def download_report():
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def add_title(text):
        pdf.set_font('Arial', 'B', 18)
        pdf.cell(0, 10, text, ln=True, align='C')
        pdf.ln(5)

    def add_section_title(text):
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 8, text, ln=True)
        pdf.ln(3)

    def add_separator():
        pdf.set_draw_color(150, 150, 150)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

    def add_checks_table(checks_list):
        pdf.set_font('Arial', 'B', 11)
        headers = ['Regla', 'Recurso', 'Estado', 'Criticidad', 'Normas', 'Recomendación']
        col_widths = [30, 50, 20, 25, 35, 30]
        col_aligns = ['C', 'L', 'C', 'C', 'L', 'L']
        line_height = 5

        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 8, header, border=1, align='C')
        pdf.ln()
        pdf.set_font('Arial', '', 9)

        for check in checks_list:
            row = [
                check.get('name', ''),
                check.get('resource', ''),
                "APROBADO" if check.get('passed') else "FALLIDO",
                check.get('criticality', 'Desconocida'),
                ", ".join(check.get('compliance', [])),
                check.get('recommendation', '')
            ]

            max_lines = 1
            for i, text in enumerate(row):
                width = col_widths[i]
                words = str(text).split()
                lines = 1
                line_width = 0
                for word in words:
                    w = pdf.get_string_width(word + ' ')
                    if line_width + w > width:
                        lines += 1
                        line_width = w
                    else:
                        line_width += w
                max_lines = max(max_lines, lines)

            row_height = max_lines * line_height
            x_start = pdf.get_x()
            y_start = pdf.get_y()

            for i, value in enumerate(row):
                pdf.set_xy(x_start + sum(col_widths[:i]), y_start)
                if i == 2:
                    pdf.set_fill_color(200, 255, 200) if check.get('passed') else pdf.set_fill_color(255, 200, 200)
                    pdf.multi_cell(col_widths[i], line_height, value, border=1, align=col_aligns[i], fill=True)
                    pdf.set_fill_color(255, 255, 255)
                else:
                    pdf.multi_cell(col_widths[i], line_height, str(value), border=1, align=col_aligns[i])

            pdf.set_y(y_start + row_height)

    add_title('Reporte de Seguridad de Azure')

    for section in ['vms', 'sql', 'storage', 'iam']:
        add_separator()
        add_section_title(f"Checks de {section.upper()}")
        add_checks_table(checks[section])

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=security_report.pdf'
    return response


@dash_app.callback(
    Output("sidebar", "className"),
    Input("toggle-button", "n_clicks"),
    prevent_initial_call=True
)
def toggle_sidebar(n_clicks):
    if n_clicks % 2 == 1:
        return "sidebar collapsed"
    return "sidebar"


if __name__ == "__main__":
    app.run(debug=True)

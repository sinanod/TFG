from flask import Flask, render_template, make_response
from dash import Dash, dcc, html
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
    layout_components = [
        html.H1("Dashboard de Seguridad de Azure", style={'textAlign': 'center', 'marginBottom': '40px'}),
    ]

    # --------- RESUMEN GENERAL DE CHECKS ----------
    all_checks = []
    for check_list in checks.values():
        all_checks.extend(check_list)

    df_checks = pd.DataFrame(all_checks)
    passed = df_checks['passed'].sum()
    failed = len(df_checks) - passed
    fig_resumen = px.pie(values=[passed, failed], names=['Aprobados', 'Fallidos'], title='Resumen de Checks')

    layout_components.append(dcc.Graph(figure=fig_resumen))

    # --------- VMs ----------
    if resources['vms']:
        df_vms = pd.DataFrame({
            'VM': [vm['name'] for vm in resources['vms']],
            'Cifrado': [
                'Sí' if 'Sin cifrado' not in vm['disk_encryption'][0] else 'No'
                for vm in resources['vms']
            ],
            'Diagnóstico': [
                'Habilitado' if 'Deshabilitados' not in vm['boot_diagnostics'] else 'Deshabilitado'
                for vm in resources['vms']
            ]
        })

        fig_vm_cifrado = px.histogram(df_vms, x='VM', color='Cifrado', title='Cifrado de discos (VMs)')
        fig_vm_diag = px.pie(df_vms, names='Diagnóstico', title='Diagnóstico de arranque (VMs)')

        layout_components += [
            html.H2("Máquinas Virtuales"),
            dcc.Graph(figure=fig_vm_cifrado),
            dcc.Graph(figure=fig_vm_diag)
        ]

    # --------- SQL ----------
    sql_checks = checks.get('sql', [])
    if sql_checks:
        sql_summary = pd.DataFrame([
            {'SQL': c['resource'], 'Check': c['name'], 'Estado': 'Fallido' if not c['passed'] else 'Aprobado'}
            for c in sql_checks if 'sql' in c['name']
        ])
        if not sql_summary.empty:
            fig_sql = px.histogram(sql_summary, x='SQL', color='Estado', title='Checks en SQL Servers')
            layout_components += [
                html.H2("SQL Servers"),
                dcc.Graph(figure=fig_sql)
            ]

    # --------- STORAGE ----------
    storage_data = resources.get('storage_accounts', [])
    if storage_data:
        df_storage = pd.DataFrame(storage_data)
        if not df_storage.empty:
            fig_storage_encrypt = px.pie(df_storage, names='encryption', title='Cifrado en Storage Accounts')
            fig_storage_public = px.pie(
                df_storage,
                names=df_storage['public_access'].map({True: 'Público', False: 'Privado'}),
                title='Acceso público en Storage Accounts'
            )
            layout_components += [
                html.H2("Storage Accounts"),
                dcc.Graph(figure=fig_storage_encrypt),
                dcc.Graph(figure=fig_storage_public)
            ]

    # --------- IAM ----------
    iam_data = resources.get('iam', [])
    if iam_data:
        df_iam = pd.DataFrame(iam_data)
        if not df_iam.empty:
            fig_iam_roles = px.histogram(df_iam, x='role', title='Distribución de Roles IAM')
            layout_components += [
                html.H2("IAM (Identidad y Acceso)"),
                dcc.Graph(figure=fig_iam_roles)
            ]

    # --------- NSGs ----------
    nsgs_checks = checks.get('nsgs', [])
    if nsgs_checks:
        fallidos = [c for c in nsgs_checks if not c['passed']]
        if fallidos:
            df_nsgs = pd.DataFrame([{'NSG': c['resource'], 'Puerto inseguro': c['description']} for c in fallidos])
            layout_components += [
                html.H2("NSGs inseguros"),
                html.Div([
                    dcc.Markdown("### Puertos abiertos al público detectados:"),
                    dcc.Graph(figure=px.bar(df_nsgs, x='NSG', title='Puertos inseguros en NSGs'))
                ])
            ]

    # --------- CRITICIDAD GLOBAL ----------
    if 'criticality' in df_checks.columns:
        fig_criticidad = px.histogram(df_checks, x='criticality', color='passed', barmode='group',
                                      title='Resumen por Criticidad')
        layout_components += [
            html.H2("Resumen por Criticidad"),
            dcc.Graph(figure=fig_criticidad)
        ]

    return html.Div(layout_components)


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


if __name__ == "__main__":
    app.run(debug=True)

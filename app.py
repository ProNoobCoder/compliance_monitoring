from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import pandas as pd
import os
import subprocess
import platform
from sqlalchemy import func, extract

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///compliance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Initialize database
db = SQLAlchemy(app)

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== DATABASE MODELS ====================

class WindowsUpdateDevice(db.Model):
    __tablename__ = 'windows_update'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    local = db.Column(db.String(50))
    types = db.Column(db.String(50))
    status = db.Column(db.String(50))
    recorded_date = db.Column(db.Date, default=datetime.utcnow().date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AntivirusDevice(db.Model):
    __tablename__ = 'antivirus'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    local = db.Column(db.String(50))
    types = db.Column(db.String(50))
    status = db.Column(db.String(50))
    recorded_date = db.Column(db.Date, default=datetime.utcnow().date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MobileEncryptionDevice(db.Model):
    __tablename__ = 'mobile_encryption'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    local = db.Column(db.String(50))
    types = db.Column(db.String(50))
    status = db.Column(db.String(50))
    recorded_date = db.Column(db.Date, default=datetime.utcnow().date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== UTILITY FUNCTIONS ====================

def ping_device(ip_address):
    try:
        # Determine ping command based on OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip_address]

        # Execute ping command
        result = subprocess.run(command, capture_output=True, timeout=5)

        if result.returncode == 0:
            return {'success': True, 'message': f'{ip_address} is reachable'}
        else:
            return {'success': False, 'message': f'{ip_address} is unreachable'}
    except subprocess.TimeoutExpired:
        return {'success': False, 'message': f'{ip_address} timeout'}
    except Exception as e:
        return {'success': False, 'message': f'Error: {str(e)}'}

def import_excel_data(file_path):
    try:
        # Read Excel file
        if file_path.endswith('.csv'):
            # For CSV, read as single sheet
            df = pd.read_csv(file_path)
            sheets = {'Sheet1': df}
        else:
            # For Excel, read all sheets
            excel_file = pd.ExcelFile(file_path)
            sheets = {sheet: excel_file.parse(sheet) for sheet in excel_file.sheet_names}

        today = datetime.utcnow().date()
        imported_count = {'windows': 0, 'antivirus': 0, 'mobile': 0}

        # Process each sheet
        for sheet_name, df in sheets.items():
            sheet_lower = sheet_name.lower().replace(' ', '')

            # Clean column names (remove spaces, lowercase)
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

            # Windows Update Sheet - check for various possible sheet names
            if ('windows' in sheet_lower and 'WINDOWSUPDATE2025' in sheet_lower) or 'windowsupdate' in sheet_lower:
                for _, row in df.iterrows():
                    hostname = str(row.get('hostname', row.get('target management name', row.get('devicename', 'Unknown'))))
                    ip_address = str(row.get('ip_address', row.get('ipaddress', row.get('ip', ''))))
                    username = str(row.get('username', row.get('user', '')))
                    local = str(row.get('local', row.get('memo1', '')))

                    device = WindowsUpdateDevice(
                        hostname=hostname,
                        username=username,
                        ip_address=ip_address,
                        local=local,
                        types='WU',
                        status='PENDING',
                        recorded_date=today
                    )
                    db.session.add(device)
                    imported_count['windows'] += 1

            # Antivirus Sheet - check for various possible sheet names
            elif ('antivirus' in sheet_lower) or ('PATTERNFILE2025' in sheet_lower and 'pattern' in sheet_lower) or 'patternfile' in sheet_lower:
                  for _, row in df.iterrows():
                    hostname = str(row.get('hostname', row.get('target management name', row.get('devicename', 'Unknown'))))
                    ip_address = str(row.get('ip_address', row.get('ipaddress', row.get('ip', ''))))
                    username = str(row.get('username', row.get('user', '')))
                    local = str(row.get('local', row.get('memo1', '')))

                    device = AntivirusDevice(
                        hostname=hostname,
                        username=username,
                        ip_address=ip_address,
                        local=local,
                        types='PF',
                        status='PENDING',
                        recorded_date=today
                    )
                    db.session.add(device)
                    imported_count['antivirus'] += 1

            # Mobile Encryption Sheet - check for various possible sheet names
            elif ('MOBILEENCRYPTION2025' in sheet_lower and 'encryption' in sheet_lower) or 'mobileencryption' in sheet_lower or 'Bitlocker' in sheet_lower:
                for _, row in df.iterrows():
                    hostname = str(row.get('hostname', row.get('target management name', row.get('devicename', 'Unknown'))))
                    ip_address = str(row.get('ip_address', row.get('ipaddress', row.get('ip', ''))))
                    username = str(row.get('username', row.get('user', '')))
                    local = str(row.get('local', row.get('memo1', '')))

                    device = MobileEncryptionDevice(
                        hostname=hostname,
                        username=username,
                        ip_address=ip_address,
                        local=local,
                        types='ME',
                        status='PENDING',
                        recorded_date=today
                    )
                    db.session.add(device)
                    imported_count['mobile'] += 1

        db.session.commit()
        return {
            'success': True,
            'message': f"Imported {imported_count['windows']} Windows Update, {imported_count['antivirus']} Antivirus, {imported_count['mobile']} Mobile Encryption records"
        }

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': f'Import error: {str(e)}'}

# ==================== ROUTES ====================

@app.route('/')
def dashboard():
    """Dashboard showing today's compliance data"""
    today = datetime.utcnow().date()

    # Get today's data for each category
    windows_devices = WindowsUpdateDevice.query.filter_by(recorded_date=today).all()
    antivirus_devices = AntivirusDevice.query.filter_by(recorded_date=today).all()
    mobile_devices = MobileEncryptionDevice.query.filter_by(recorded_date=today).all()

    return render_template('dashboard.html',
                         windows_devices=windows_devices,
                         antivirus_devices=antivirus_devices,
                         mobile_devices=mobile_devices,
                         today=today)

@app.route('/weekly')
def weekly_report():
    """Weekly compliance report with charts"""
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)

    # Get weekly data
    windows_weekly = WindowsUpdateDevice.query.filter(
        WindowsUpdateDevice.recorded_date >= week_ago
    ).all()
    antivirus_weekly = AntivirusDevice.query.filter(
        AntivirusDevice.recorded_date >= week_ago
    ).all()
    mobile_weekly = MobileEncryptionDevice.query.filter(
        MobileEncryptionDevice.recorded_date >= week_ago
    ).all()

    # Prepare chart data (count per day) - convert to list of lists
    windows_chart_query = db.session.query(
        WindowsUpdateDevice.recorded_date,
        func.count(WindowsUpdateDevice.id)
    ).filter(WindowsUpdateDevice.recorded_date >= week_ago).group_by(
        WindowsUpdateDevice.recorded_date
    ).all()

    windows_chart = [[str(date), count] for date, count in windows_chart_query]

    antivirus_chart_query = db.session.query(
        AntivirusDevice.recorded_date,
        func.count(AntivirusDevice.id)
    ).filter(AntivirusDevice.recorded_date >= week_ago).group_by(
        AntivirusDevice.recorded_date
    ).all()

    antivirus_chart = [[str(date), count] for date, count in antivirus_chart_query]

    mobile_chart_query = db.session.query(
        MobileEncryptionDevice.recorded_date,
        func.count(MobileEncryptionDevice.id)
    ).filter(MobileEncryptionDevice.recorded_date >= week_ago).group_by(
        MobileEncryptionDevice.recorded_date
    ).all()

    mobile_chart = [[str(date), count] for date, count in mobile_chart_query]

    return render_template('weekly.html',
                         windows_weekly=windows_weekly,
                         antivirus_weekly=antivirus_weekly,
                         mobile_weekly=mobile_weekly,
                         windows_chart=windows_chart,
                         antivirus_chart=antivirus_chart,
                         mobile_chart=mobile_chart,
                         start_date=week_ago,
                         end_date=today)

@app.route('/monthly')
def monthly_report():
    today = datetime.utcnow().date()
    month_ago = today - timedelta(days=30)

    # Get monthly data
    windows_monthly = WindowsUpdateDevice.query.filter(
        WindowsUpdateDevice.recorded_date >= month_ago
    ).all()
    antivirus_monthly = AntivirusDevice.query.filter(
        AntivirusDevice.recorded_date >= month_ago
    ).all()
    mobile_monthly = MobileEncryptionDevice.query.filter(
        MobileEncryptionDevice.recorded_date >= month_ago
    ).all()

    # Prepare chart data (count per week)
    windows_chart_query = db.session.query(
        WindowsUpdateDevice.recorded_date,
        func.count(WindowsUpdateDevice.id)
    ).filter(WindowsUpdateDevice.recorded_date >= month_ago).group_by(
        WindowsUpdateDevice.recorded_date
    ).all()

    windows_chart = [{"date": str(date), "count": count} for date, count in windows_chart_query]


    antivirus_chart_query = db.session.query(
        AntivirusDevice.recorded_date,
        func.count(AntivirusDevice.id)
    ).filter(AntivirusDevice.recorded_date >= month_ago).group_by(
        AntivirusDevice.recorded_date
    ).all()

    antivirus_chart = [{"date": str(date), "count": count} for date, count in antivirus_chart_query]

    mobile_chart_query = db.session.query(
        MobileEncryptionDevice.recorded_date,
        func.count(MobileEncryptionDevice.id)
    ).filter(MobileEncryptionDevice.recorded_date >= month_ago).group_by(
        MobileEncryptionDevice.recorded_date
    ).all()

    mobile_chart = [{"date": str(date), "count": count} for date, count in mobile_chart_query]

    return render_template('monthly.html',
                         windows_monthly=windows_monthly,
                         antivirus_monthly=antivirus_monthly,
                         mobile_monthly=mobile_monthly,
                         windows_chart=windows_chart,
                         antivirus_chart=antivirus_chart,
                         mobile_chart=mobile_chart,
                         start_date=month_ago,
                         end_date=today)

@app.route('/manage')
def manage():
    # Get all records and convert to dictionaries
    windows_all = WindowsUpdateDevice.query.order_by(WindowsUpdateDevice.recorded_date.desc()).all()
    antivirus_all = AntivirusDevice.query.order_by(AntivirusDevice.recorded_date.desc()).all()
    mobile_all = MobileEncryptionDevice.query.order_by(MobileEncryptionDevice.recorded_date.desc()).all()

    # Convert to dictionaries for JSON serialization
    windows_dict = [{
        'id': d.id,
        'hostname': d.hostname,
        'username': d.username,
        'ip_address': d.ip_address,
        'local': d.local,
        'types': d.types,
        'status': d.status,
        'recorded_date': d.recorded_date.strftime('%Y-%m-%d') if d.recorded_date else ''
    } for d in windows_all]

    antivirus_dict = [{
        'id': d.id,
        'hostname': d.hostname,
        'username': d.username,
        'ip_address': d.ip_address,
        'local': d.local,
        'types': d.types,
        'status': d.status,
        'recorded_date': d.recorded_date.strftime('%Y-%m-%d') if d.recorded_date else ''
    } for d in antivirus_all]

    mobile_dict = [{
        'id': d.id,
        'hostname': d.hostname,
        'username': d.username,
        'ip_address': d.ip_address,
        'local': d.local,
        'types': d.types,
        'status': d.status,
        'recorded_date': d.recorded_date.strftime('%Y-%m-%d') if d.recorded_date else ''
    } for d in mobile_all]

    return render_template('manage.html',
                         windows_all=windows_all,
                         antivirus_all=antivirus_all,
                         mobile_all=mobile_all,
                         windows_dict=windows_dict,
                         antivirus_dict=antivirus_dict,
                         mobile_dict=mobile_dict)

@app.route('/import', methods=['POST'])
def import_data():
    """Handle file upload and data import"""
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    if file:
        # Save file
        filename = f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Import data
        result = import_excel_data(filepath)

        if result['success']:
            flash(result['message'], 'success')
        else:
            flash(result['message'], 'error')

        return redirect(url_for('dashboard'))

@app.route('/ping', methods=['POST'])
def ping():
    """Ping a single device"""
    data = request.json
    ip_address = data.get('ip_address')

    if not ip_address:
        return jsonify({'success': False, 'message': 'No IP address provided'})

    result = ping_device(ip_address)
    return jsonify(result)

# ==================== CRUD OPERATIONS ====================

@app.route('/add/<category>', methods=['POST'])
def add_record(category):
    """Add new record"""
    try:
        if category == 'windows':
            device = WindowsUpdateDevice(
                hostname=request.form['hostname'],
                username=request.form['username'],
                ip_address=request.form['ip_address'],
                local=request.form['local'],
                types=request.form['types'],
                status=request.form['status'],
                recorded_date=datetime.strptime(request.form['recorded_date'], '%Y-%m-%d').date()
            )
        elif category == 'antivirus':
            device = AntivirusDevice(
                hostname=request.form['hostname'],
                username=request.form['username'],
                ip_address=request.form['ip_address'],
                local=request.form['local'],
                types=request.form['types'],
                status=request.form['status'],
                recorded_date=datetime.strptime(request.form['recorded_date'], '%Y-%m-%d').date()
            )
        elif category == 'mobile':
            device = MobileEncryptionDevice(
                hostname=request.form['hostname'],
                username=request.form['username'],
                ip_address=request.form['ip_address'],
                local=request.form['local'],
                types=request.form['types'],
                status=request.form['status'],
                recorded_date=datetime.strptime(request.form['recorded_date'], '%Y-%m-%d').date()
            )
        else:
            flash('Invalid category', 'error')
            return redirect(url_for('manage'))

        db.session.add(device)
        db.session.commit()
        flash(f'{category.title()} record added successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding record: {str(e)}', 'error')

    return redirect(url_for('manage'))

@app.route('/update/<category>/<int:id>', methods=['POST'])
def update_record(category, id):
    try:
        if category == 'windows':
            device = WindowsUpdateDevice.query.get_or_404(id)
            device.hostname = request.form['hostname']
            device.username = request.form['username']
            device.ip_address = request.form['ip_address']
            device.local = request.form['local']
            device.types = request.form['types']
            device.status = request.form['status']
            device.recorded_date = datetime.strptime(request.form['recorded_date'], '%Y-%m-%d').date()
        elif category == 'antivirus':
            device = AntivirusDevice.query.get_or_404(id)
            device.hostname = request.form['hostname']
            device.username = request.form['username']
            device.ip_address = request.form['ip_address']
            device.local = request.form['local']
            device.types = request.form['types']
            device.status = request.form['status']
            device.recorded_date = datetime.strptime(request.form['recorded_date'], '%Y-%m-%d').date()
        elif category == 'mobile':
            device = MobileEncryptionDevice.query.get_or_404(id)
            device.hostname = request.form['hostname']
            device.username = request.form['username']
            device.ip_address = request.form['ip_address']
            device.local = request.form['local']
            device.types = request.form['types']
            device.status = request.form['status']
            device.recorded_date = datetime.strptime(request.form['recorded_date'], '%Y-%m-%d').date()
        else:
            flash('Invalid category', 'error')
            return redirect(url_for('manage'))

        db.session.commit()
        flash(f'{category.title()} record updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating record: {str(e)}', 'error')

    return redirect(url_for('manage'))

@app.route('/delete/<category>/<int:id>', methods=['POST'])
def delete_record(category, id):
    """Delete record"""
    try:
        if category == 'windows':
            device = WindowsUpdateDevice.query.get_or_404(id)
        elif category == 'antivirus':
            device = AntivirusDevice.query.get_or_404(id)
        elif category == 'mobile':
            device = MobileEncryptionDevice.query.get_or_404(id)
        else:
            flash('Invalid category', 'error')
            return redirect(url_for('manage'))

        db.session.delete(device)
        db.session.commit()
        flash(f'{category.title()} record deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting record: {str(e)}', 'error')

    return redirect(url_for('manage'))

# ==================== INITIALIZE DATABASE ====================

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

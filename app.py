from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
import os
import pytz
from models import db, User, Complaint, Issue, Repair, Replacement, Company, Role, Unit, AccountType, IssueItem, BookingForm
from models import Category, ReportedBy, Priority, Status, Type
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///propertyhub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
db.init_app(app)


# Add template filter for Malaysia timezone
@app.template_filter('malaysia_time')
def malaysia_time_filter(utc_dt):
    """Convert UTC datetime to Malaysia timezone"""
    if utc_dt is None:
        return ""
    malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
    if utc_dt.tzinfo is None:
        utc_dt = pytz.utc.localize(utc_dt)
    malaysia_time = utc_dt.astimezone(malaysia_tz)
    return malaysia_time.strftime('%b %d, %Y, %I:%M %p')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Permission-based decorators
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_permission(permission):
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# Specific permission decorators
def complaints_view_required(f):
    return permission_required('can_view_complaints')(f)


def complaints_manage_required(f):
    return permission_required('can_manage_complaints')(f)


def issues_view_required(f):
    return permission_required('can_view_issues')(f)


def issues_manage_required(f):
    return permission_required('can_manage_issues')(f)


def repairs_view_required(f):
    return permission_required('can_view_repairs')(f)


def repairs_manage_required(f):
    return permission_required('can_manage_repairs')(f)


def replacements_view_required(f):
    return permission_required('can_view_replacements')(f)


def replacements_manage_required(f):
    return permission_required('can_manage_replacements')(f)


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('You have been logged in successfully', 'success')

            # Redirect cleaners to their dashboard
            if user.is_cleaner:
                return redirect(url_for('cleaner_dashboard'))

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your email and password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if password and confirm_password match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered. Please use a different email or login', 'danger')
            return redirect(url_for('register'))

        # Get default company and role
        default_company = Company.query.first()
        if not default_company:
            default_company = Company(name="Default Company")
            db.session.add(default_company)
            db.session.commit()

        # Find a non-admin role
        user_role = Role.query.filter_by(name="Manager").first()
        if not user_role:
            user_role = Role.query.filter(Role.is_admin.is_(False)).first()
        if not user_role:
            # If no non-admin role exists, create a basic user role
            user_role = Role(name="User",
                             can_view_complaints=True,
                             can_view_issues=True,
                             can_view_repairs=True,
                             can_view_replacements=True)
            db.session.add(user_role)
            db.session.commit()

        # Get default account type (Standard)
        default_account_type = AccountType.query.filter_by(name="Standard Account").first()
        if not default_account_type:
            default_account_type = AccountType.query.first()

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            company_id=default_company.id,
            role_id=user_role.id,
            account_type_id=default_account_type.id  # Set default account type
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now sign in', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # Redirect cleaners to cleaner dashboard
    if current_user.is_cleaner:
        return redirect(url_for('cleaner_dashboard'))

    # Filter records to only show those belonging to the user's company
    # but respect the role permissions
    user_company_id = current_user.company_id

    complaints = []
    repairs = []
    replacements = []
    units = []

    if current_user.has_permission('can_view_complaints'):
        complaints = Complaint.query.filter_by(company_id=user_company_id).all()

    if current_user.has_permission('can_view_issues'):
        issues = Issue.query.filter_by(company_id=user_company_id).all()

    if current_user.has_permission('can_view_repairs'):
        repairs = Repair.query.filter_by(company_id=user_company_id).all()

    if current_user.has_permission('can_view_replacements'):
        replacements = Replacement.query.filter_by(company_id=user_company_id).all()

    # Get units for this company
    units = Unit.query.filter_by(company_id=user_company_id).all()

    return render_template('dashboard.html', complaints=complaints, repairs=repairs, replacements=replacements,
                           units=units)



# I add (Manually)
@app.route('/issues')
@login_required
@issues_view_required
def issues():
    # Filter records to only show those belonging to the user's company
    user_company_id = current_user.company_id
    issues = []

    if current_user.has_permission('can_view_issues'):
        issues = Issue.query.filter_by(company_id=user_company_id).all()

    # Get units for this company for the form
    units = Unit.query.filter_by(company_id=user_company_id).all()

    # Get categories, priorities, statuses, etc.
    categories = Category.query.all()
    reported_by_options = ReportedBy.query.all()
    priorities = Priority.query.all()
    statuses = Status.query.all()
    types = Type.query.all()

    # Get issue items with their categories
    issue_items_by_category = {}
    for category in categories:
        issue_items_by_category[category.id] = IssueItem.query.filter_by(category_id=category.id).all()

    # Add current date/time for template calculations
    now = datetime.now()

    return render_template('issues.html',
                           issues=issues,
                           units=units,
                           categories=categories,
                           reported_by_options=reported_by_options,
                           priorities=priorities,
                           statuses=statuses,
                           types=types,
                           issue_items_by_category=issue_items_by_category,
                           now=now,
                           timedelta=timedelta)


# Update your add_issue route to handle the issue_item field:
@app.route('/add_issue', methods=['POST'])
@login_required
@permission_required('can_manage_issues')
def add_issue():
    description = request.form['description']
    unit_id = request.form['unit_id']

    # New fields
    category_id = request.form.get('category_id') or None
    reported_by_id = request.form.get('reported_by_id') or None
    priority_id = request.form.get('priority_id') or None
    status_id = request.form.get('status_id') or None
    type_id = request.form.get('type_id') or None
    issue_item_id = request.form.get('issue_item_id') or None

    # Handle custom issue item
    custom_issue = request.form.get('custom_issue', '').strip()
    if custom_issue and category_id:
        # Check if this custom issue already exists
        existing_item = IssueItem.query.filter_by(name=custom_issue, category_id=category_id).first()
        if existing_item:
            issue_item_id = existing_item.id
        else:
            # Create a new issue item
            new_issue_item = IssueItem(name=custom_issue, category_id=category_id)
            db.session.add(new_issue_item)
            db.session.flush()  # Get the ID before committing
            issue_item_id = new_issue_item.id

    solution = request.form.get('solution', '')
    guest_name = request.form.get('guest_name', '')

    # Fix for cost field - convert empty string to None
    cost_value = request.form.get('cost', '')
    cost = float(cost_value) if cost_value.strip() else None

    assigned_to = request.form.get('assigned_to', '')

    # Get the unit number from the selected unit
    unit = Unit.query.get(unit_id)
    if not unit:
        flash('Invalid unit selected', 'danger')
        return redirect(url_for('issues'))

    # Check if the unit belongs to the user's company
    if unit.company_id != current_user.company_id:
        flash('You do not have permission to add issues for this unit', 'danger')
        return redirect(url_for('issues'))

    new_issue = Issue(
        description=description,
        unit=unit.unit_number,
        unit_id=unit_id,
        category_id=category_id,
        reported_by_id=reported_by_id,
        priority_id=priority_id,
        status_id=status_id,
        type_id=type_id,
        issue_item_id=issue_item_id,
        solution=solution,
        guest_name=guest_name,
        cost=cost,
        assigned_to=assigned_to,
        author=current_user,
        company_id=current_user.company_id
    )
    db.session.add(new_issue)
    db.session.commit()

    flash('Issue added successfully', 'success')
    return redirect(url_for('issues'))


# Update your update_issue route to handle the issue_item field:
@app.route('/update_issue/<int:id>', methods=['POST'])
@login_required
@permission_required('can_manage_issues')
def update_issue(id):
    issue = Issue.query.get_or_404(id)

    # Ensure the current user's company matches the issue's company
    if issue.company_id != current_user.company_id:
        flash('You are not authorized to update this issue', 'danger')
        return redirect(url_for('issues'))

    unit_id = request.form.get('unit_id')

    # Get the unit if unit_id is provided
    if unit_id:
        unit = Unit.query.get(unit_id)
        if not unit:
            flash('Invalid unit selected', 'danger')
            return redirect(url_for('issues'))

        # Check if the unit belongs to the user's company
        if unit.company_id != current_user.company_id:
            flash('You do not have permission to use this unit', 'danger')
            return redirect(url_for('issues'))

        issue.unit = unit.unit_number
        issue.unit_id = unit_id

    # Update fields
    issue.description = request.form['description']

    # Handle optional fields
    issue.category_id = request.form.get('category_id') or None
    issue.reported_by_id = request.form.get('reported_by_id') or None
    issue.priority_id = request.form.get('priority_id') or None
    issue.status_id = request.form.get('status_id') or None
    issue.type_id = request.form.get('type_id') or None

    # Handle issue item
    issue_item_id = request.form.get('issue_item_id') or None
    custom_issue = request.form.get('custom_issue', '').strip()

    if custom_issue and issue.category_id:
        # Check if this custom issue already exists
        existing_item = IssueItem.query.filter_by(name=custom_issue, category_id=issue.category_id).first()
        if existing_item:
            issue_item_id = existing_item.id
        else:
            # Create a new issue item
            new_issue_item = IssueItem(name=custom_issue, category_id=issue.category_id)
            db.session.add(new_issue_item)
            db.session.flush()  # Get the ID before committing
            issue_item_id = new_issue_item.id

    issue.issue_item_id = issue_item_id
    issue.solution = request.form.get('solution', '')
    issue.guest_name = request.form.get('guest_name', '')

    # Fix for cost field
    cost_value = request.form.get('cost', '')
    issue.cost = float(cost_value) if cost_value.strip() else None

    issue.assigned_to = request.form.get('assigned_to', '')

    db.session.commit()
    flash('Issue updated successfully', 'success')
    return redirect(url_for('issues'))


@app.route('/delete_issue/<int:id>')
@login_required
@permission_required('can_manage_issues')
def delete_issue(id):
    issue = Issue.query.get_or_404(id)

    # Ensure the current user's company matches the issue's company
    if issue.company_id != current_user.company_id:
        flash('You are not authorized to delete this issue', 'danger')
        return redirect(url_for('issues'))

    db.session.delete(issue)
    db.session.commit()

    flash('Issue deleted successfully', 'success')
    return redirect(url_for('issues'))


# Add a new API endpoint to get issue items for a category:
@app.route('/api/get_issue_items/<int:category_id>')
@login_required
def get_issue_items(category_id):
    issue_items = IssueItem.query.filter_by(category_id=category_id).all()
    items_list = [{'id': item.id, 'name': item.name} for item in issue_items]
    return jsonify(items_list)


# Update your get_issue API endpoint to include issue_item_id:
@app.route('/api/issue/<int:id>')
@login_required
@permission_required('can_view_issues')
def get_issue(id):
    issue = Issue.query.get_or_404(id)

    # Ensure the current user's company matches the issue's company
    if issue.company_id != current_user.company_id:
        return jsonify({'error': 'Not authorized'}), 403

    return jsonify({
        'id': issue.id,
        'description': issue.description,
        'unit_id': issue.unit_id,
        'category_id': issue.category_id,
        'reported_by_id': issue.reported_by_id,
        'priority_id': issue.priority_id,
        'status_id': issue.status_id,
        'type_id': issue.type_id,
        'issue_item_id': issue.issue_item_id,
        'solution': issue.solution,
        'guest_name': issue.guest_name,
        'cost': float(issue.cost) if issue.cost else 0,
        'assigned_to': issue.assigned_to
    })

# Create routes for unit management
@app.route('/manage_units')
@login_required
def manage_units():
    # Redirect cleaners to cleaner dashboard
    if current_user.is_cleaner:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('cleaner_dashboard'))

    # Get current user's units
    user_company_id = current_user.company_id
    units = Unit.query.filter_by(company_id=user_company_id).all()

    return render_template('manage_units.html', units=units)


@app.route('/add_unit', methods=['GET', 'POST'])
@login_required
def add_unit():
    if request.method == 'POST':
        unit_number = request.form['unit_number']
        description = request.form['description']
        floor = request.form['floor'] or None
        building = request.form['building']
        is_occupied = 'is_occupied' in request.form

        # Get values for new fields
        toilet_count = request.form.get('toilet_count') or None
        towel_count = request.form.get('towel_count') or None
        max_pax = request.form.get('max_pax') or None

        # Convert to integers if not None
        if toilet_count:
            toilet_count = int(toilet_count)
        if towel_count:
            towel_count = int(towel_count)
        if max_pax:
            max_pax = int(max_pax)

        # Get current user's company
        company_id = current_user.company_id
        company = Company.query.get(company_id)

        # Check if unit number already exists in this company only
        existing_unit = Unit.query.filter_by(unit_number=unit_number, company_id=company_id).first()
        if existing_unit:
            flash('This unit number already exists in your company', 'danger')
            return redirect(url_for('add_unit'))

        # Check if company has reached their unit limit
        current_units_count = Unit.query.filter_by(company_id=company_id).count()
        max_units = company.account_type.max_units

        if current_units_count >= max_units:
            flash(
                f'Your company has reached the limit of {max_units} units. Please contact admin to upgrade your account.',
                'danger')
            return redirect(url_for('manage_units'))

        # Create new unit with the new fields
        new_unit = Unit(
            unit_number=unit_number,
            description=description,
            floor=floor,
            building=building,
            company_id=company_id,
            is_occupied=is_occupied,
            toilet_count=toilet_count,
            towel_count=towel_count,
            max_pax=max_pax
        )

        db.session.add(new_unit)
        db.session.commit()

        flash('Unit added successfully', 'success')
        return redirect(url_for('manage_units'))

    return render_template('add_unit_user.html')


@app.route('/edit_unit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_unit(id):
    unit = Unit.query.get_or_404(id)

    # Check if the unit belongs to the user's company
    if unit.company_id != current_user.company_id:
        flash('You do not have permission to edit this unit', 'danger')
        return redirect(url_for('manage_units'))

    if request.method == 'POST':
        unit.unit_number = request.form['unit_number']
        unit.description = request.form['description']
        unit.floor = request.form['floor'] or None
        unit.building = request.form['building']
        unit.is_occupied = 'is_occupied' in request.form

        # Update new fields
        toilet_count = request.form.get('toilet_count') or None
        towel_count = request.form.get('towel_count') or None
        max_pax = request.form.get('max_pax') or None

        # Convert to integers if not None
        if toilet_count:
            unit.toilet_count = int(toilet_count)
        else:
            unit.toilet_count = None

        if towel_count:
            unit.towel_count = int(towel_count)
        else:
            unit.towel_count = None

        if max_pax:
            unit.max_pax = int(max_pax)
        else:
            unit.max_pax = None

        db.session.commit()
        flash('Unit updated successfully', 'success')
        return redirect(url_for('manage_units'))

    return render_template('edit_unit_user.html', unit=unit)

@app.route('/delete_unit/<int:id>')
@login_required
def delete_unit(id):
    unit = Unit.query.get_or_404(id)

    # Check if the unit belongs to the user's company
    if unit.company_id != current_user.company_id:
        flash('You do not have permission to delete this unit', 'danger')
        return redirect(url_for('manage_units'))

    # Check if unit is in use
    if unit.complaints or unit.repairs or unit.replacements:
        flash('Cannot delete unit that is referenced by complaints, repairs, or replacements', 'danger')
        return redirect(url_for('manage_units'))

    db.session.delete(unit)
    db.session.commit()

    flash('Unit deleted successfully', 'success')
    return redirect(url_for('manage_units'))


# API route to get units for the current user's company
@app.route('/api/get_units')
@login_required
def get_units():
    company_id = current_user.company_id
    units = Unit.query.filter_by(company_id=company_id).all()
    units_list = [{'id': unit.id, 'unit_number': unit.unit_number} for unit in units]
    return jsonify(units_list)


# Repair routes
@app.route('/add_repair', methods=['POST'])
@login_required
@permission_required('can_manage_repairs')
def add_repair():
    item = request.form['item']
    remark = request.form['remark']
    unit_id = request.form['unit_id']
    status = request.form['status']

    # Get the unit
    unit = Unit.query.get(unit_id)
    if not unit:
        flash('Invalid unit selected', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the unit belongs to the user's company
    if unit.company_id != current_user.company_id:
        flash('You do not have permission to add repairs for this unit', 'danger')
        return redirect(url_for('dashboard'))

    new_repair = Repair(
        item=item,
        remark=remark,
        unit=unit.unit_number,  # Keep the unit number for backward compatibility
        unit_id=unit_id,  # Store the reference to the unit model
        status=status,
        author=current_user,
        company_id=current_user.company_id
    )
    db.session.add(new_repair)
    db.session.commit()

    flash('Repair request added successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/update_repair/<int:id>', methods=['POST'])
@login_required
@permission_required('can_manage_repairs')
def update_repair(id):
    repair = Repair.query.get_or_404(id)

    # Ensure the current user's company matches the repair's company
    if repair.company_id != current_user.company_id:
        flash('You are not authorized to update this repair request', 'danger')
        return redirect(url_for('dashboard'))

    unit_id = request.form.get('unit_id')

    # Get the unit if unit_id is provided
    if unit_id:
        unit = Unit.query.get(unit_id)
        if not unit:
            flash('Invalid unit selected', 'danger')
            return redirect(url_for('dashboard'))

        # Check if the unit belongs to the user's company
        if unit.company_id != current_user.company_id:
            flash('You do not have permission to use this unit', 'danger')
            return redirect(url_for('dashboard'))

        repair.unit = unit.unit_number
        repair.unit_id = unit_id

    repair.item = request.form['item']
    repair.remark = request.form['remark']
    repair.status = request.form['status']

    db.session.commit()
    flash('Repair request updated successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete_repair/<int:id>')
@login_required
@permission_required('can_manage_repairs')
def delete_repair(id):
    repair = Repair.query.get_or_404(id)

    # Ensure the current user's company matches the repair's company
    if repair.company_id != current_user.company_id:
        flash('You are not authorized to delete this repair request', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(repair)
    db.session.commit()

    flash('Repair request deleted successfully', 'success')
    return redirect(url_for('dashboard'))


# Replacement routes
@app.route('/add_replacement', methods=['POST'])
@login_required
@permission_required('can_manage_replacements')
def add_replacement():
    item = request.form['item']
    remark = request.form['remark']
    unit_id = request.form['unit_id']
    status = request.form['status']

    # Get the unit
    unit = Unit.query.get(unit_id)
    if not unit:
        flash('Invalid unit selected', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the unit belongs to the user's company
    if unit.company_id != current_user.company_id:
        flash('You do not have permission to add replacements for this unit', 'danger')
        return redirect(url_for('dashboard'))

    new_replacement = Replacement(
        item=item,
        remark=remark,
        unit=unit.unit_number,  # Keep the unit number for backward compatibility
        unit_id=unit_id,  # Store the reference to the unit model
        status=status,
        author=current_user,
        company_id=current_user.company_id
    )
    db.session.add(new_replacement)
    db.session.commit()

    flash('Replacement request added successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/update_replacement/<int:id>', methods=['POST'])
@login_required
@permission_required('can_manage_replacements')
def update_replacement(id):
    replacement = Replacement.query.get_or_404(id)

    # Ensure the current user's company matches the replacement's company
    if replacement.company_id != current_user.company_id:
        flash('You are not authorized to update this replacement request', 'danger')
        return redirect(url_for('dashboard'))

    unit_id = request.form.get('unit_id')

    # Get the unit if unit_id is provided
    if unit_id:
        unit = Unit.query.get(unit_id)
        if not unit:
            flash('Invalid unit selected', 'danger')
            return redirect(url_for('dashboard'))

        # Check if the unit belongs to the user's company
        if unit.company_id != current_user.company_id:
            flash('You do not have permission to use this unit', 'danger')
            return redirect(url_for('dashboard'))

        replacement.unit = unit.unit_number
        replacement.unit_id = unit_id

    replacement.item = request.form['item']
    replacement.remark = request.form['remark']
    replacement.status = request.form['status']

    db.session.commit()
    flash('Replacement request updated successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete_replacement/<int:id>')
@login_required
@permission_required('can_manage_replacements')
def delete_replacement(id):
    replacement = Replacement.query.get_or_404(id)

    # Ensure the current user's company matches the replacement's company
    if replacement.company_id != current_user.company_id:
        flash('You are not authorized to delete this replacement request', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(replacement)
    db.session.commit()

    flash('Replacement request deleted successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    companies = Company.query.all()
    roles = Role.query.all()
    complaints = Complaint.query.all()
    repairs = Repair.query.all()
    replacements = Replacement.query.all()
    units = Unit.query.all()
    issues = Issue.query.all()

    # Get count of each type by company
    company_stats = []
    for company in companies:
        company_users = User.query.filter_by(company_id=company.id).count()
        company_complaints = Complaint.query.filter_by(company_id=company.id).count()
        company_issues = Issue.query.filter_by(company_id=company.id).count()
        company_repairs = Repair.query.filter_by(company_id=company.id).count()
        company_replacements = Replacement.query.filter_by(company_id=company.id).count()
        company_units = Unit.query.filter_by(company_id=company.id).count()

        company_stats.append({
            'name': company.name,
            'users': company_users,
            'complaints': company_complaints,
            'issues': company_issues,
            'repairs': company_repairs,
            'replacements': company_replacements,
            'units': company_units
        })

    return render_template('admin/dashboard.html',
                           users=users,
                           companies=companies,
                           roles=roles,
                           complaints=complaints,
                           issues=issues,
                           repairs=repairs,
                           replacements=replacements,
                           units=units,
                           company_stats=company_stats)


# Admin routes for units
@app.route('/admin/units')
@login_required
@admin_required
def admin_units():
    units = Unit.query.all()
    return render_template('admin/units.html', units=units)


@app.route('/admin/add_unit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_unit():
    companies = Company.query.all()

    if request.method == 'POST':
        unit_number = request.form['unit_number']
        description = request.form['description']
        floor = request.form['floor'] or None
        building = request.form['building']
        company_id = request.form['company_id']
        is_occupied = 'is_occupied' in request.form

        # Get values for new fields
        toilet_count = request.form.get('toilet_count') or None
        towel_count = request.form.get('towel_count') or None
        max_pax = request.form.get('max_pax') or None

        # Convert to integers if not None
        if toilet_count:
            toilet_count = int(toilet_count)
        if towel_count:
            towel_count = int(towel_count)
        if max_pax:
            max_pax = int(max_pax)

        # Check if unit already exists in the selected company
        existing_unit = Unit.query.filter_by(unit_number=unit_number, company_id=company_id).first()
        if existing_unit:
            flash('Unit number already exists in this company', 'danger')
            return redirect(url_for('admin_add_unit'))

        new_unit = Unit(
            unit_number=unit_number,
            description=description,
            floor=floor,
            building=building,
            company_id=company_id,
            is_occupied=is_occupied,
            toilet_count=toilet_count,
            towel_count=towel_count,
            max_pax=max_pax
        )

        db.session.add(new_unit)
        db.session.commit()

        flash('Unit added successfully', 'success')
        return redirect(url_for('admin_units'))

    return render_template('admin/add_unit.html', companies=companies)


@app.route('/admin/edit_unit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_unit(id):
    unit = Unit.query.get_or_404(id)
    companies = Company.query.all()

    if request.method == 'POST':
        unit.unit_number = request.form['unit_number']
        unit.description = request.form['description']
        unit.floor = request.form['floor'] or None
        unit.building = request.form['building']
        unit.company_id = request.form['company_id']
        unit.is_occupied = 'is_occupied' in request.form

        # Update new fields
        toilet_count = request.form.get('toilet_count') or None
        towel_count = request.form.get('towel_count') or None
        max_pax = request.form.get('max_pax') or None

        # Convert to integers if not None
        if toilet_count:
            unit.toilet_count = int(toilet_count)
        else:
            unit.toilet_count = None

        if towel_count:
            unit.towel_count = int(towel_count)
        else:
            unit.towel_count = None

        if max_pax:
            unit.max_pax = int(max_pax)
        else:
            unit.max_pax = None

        db.session.commit()
        flash('Unit updated successfully', 'success')
        return redirect(url_for('admin_units'))

    return render_template('admin/edit_unit.html', unit=unit, companies=companies)

@app.route('/admin/delete_unit/<int:id>')
@login_required
@admin_required
def admin_delete_unit(id):
    unit = Unit.query.get_or_404(id)

    # Check if unit is in use
    if unit.complaints or unit.repairs or unit.replacements:
        flash('Cannot delete unit that is referenced by complaints, repairs, or replacements', 'danger')
        return redirect(url_for('admin_units'))

    db.session.delete(unit)
    db.session.commit()

    flash('Unit deleted successfully', 'success')
    return redirect(url_for('admin_units'))


# User management routes
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_user():
    # Get all companies and roles for the form
    companies = Company.query.all()
    roles = Role.query.all()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        company_id = request.form['company_id']
        role_id = request.form['role_id']
        is_cleaner = 'is_cleaner' in request.form  # Check if is_cleaner checkbox is checked

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered', 'danger')
            return redirect(url_for('admin_add_user'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            name=name,
            email=email,
            password=hashed_password,
            company_id=company_id,
            role_id=role_id,
            is_cleaner=is_cleaner  # Add is_cleaner field
        )
        db.session.add(new_user)
        db.session.commit()

        flash('User added successfully', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/add_user.html', companies=companies, roles=roles)



@app.route('/admin/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(id):
    user = User.query.get_or_404(id)
    companies = Company.query.all()
    roles = Role.query.all()

    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.company_id = request.form['company_id']
        user.role_id = request.form['role_id']
        user.is_cleaner = 'is_cleaner' in request.form  # Update is_cleaner field

        # Only update password if provided
        if request.form['password'].strip():
            user.password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/edit_user.html', user=user, companies=companies, roles=roles)


@app.route('/admin/delete_user/<int:id>')
@login_required
@admin_required
def admin_delete_user(id):
    if id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_users'))


# Company routes
@app.route('/admin/companies')
@login_required
@admin_required
def admin_companies():
    companies = Company.query.all()
    return render_template('admin/companies.html', companies=companies)


@app.route('/admin/add_company', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_company():
    # Get all account types for the form
    account_types = AccountType.query.all()

    if request.method == 'POST':
        name = request.form['name']
        account_type_id = request.form['account_type_id']

        # Check if company already exists
        company = Company.query.filter_by(name=name).first()
        if company:
            flash('Company already exists', 'danger')
            return redirect(url_for('admin_add_company'))

        new_company = Company(
            name=name,
            account_type_id=account_type_id
        )
        db.session.add(new_company)
        db.session.commit()

        flash('Company added successfully', 'success')
        return redirect(url_for('admin_companies'))

    return render_template('admin/add_company.html', account_types=account_types)


@app.route('/admin/edit_company/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_company(id):
    company = Company.query.get_or_404(id)
    account_types = AccountType.query.all()

    if request.method == 'POST':
        company.name = request.form['name']
        company.account_type_id = request.form['account_type_id']
        db.session.commit()
        flash('Company updated successfully', 'success')
        return redirect(url_for('admin_companies'))

    return render_template('admin/edit_company.html', company=company, account_types=account_types)


@app.route('/admin/delete_company/<int:id>')
@login_required
@admin_required
def admin_delete_company(id):
    company = Company.query.get_or_404(id)

    # Check if company has users or units
    if company.users or company.units:
        flash('Cannot delete company with existing users or units', 'danger')
        return redirect(url_for('admin_companies'))

    db.session.delete(company)
    db.session.commit()

    flash('Company deleted successfully', 'success')
    return redirect(url_for('admin_companies'))


# Role routes
@app.route('/admin/roles')
@login_required
@admin_required
def admin_roles():
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)


@app.route('/admin/add_role', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_role():
    if request.method == 'POST':
        name = request.form['name']

        # Check if role already exists
        role = Role.query.filter_by(name=name).first()
        if role:
            flash('Role already exists', 'danger')
            return redirect(url_for('admin_add_role'))

        # Create new role with permissions
        new_role = Role(
            name=name,
            can_view_complaints='can_view_complaints' in request.form,
            can_view_issues='can_view_issues' in request.form,
            can_manage_complaints='can_manage_complaints' in request.form,
            can_view_repairs='can_view_repairs' in request.form,
            can_manage_repairs='can_manage_repairs' in request.form,
            can_view_replacements='can_view_replacements' in request.form,
            can_manage_replacements='can_manage_replacements' in request.form,
            is_admin='is_admin' in request.form,
            can_manage_users='can_manage_users' in request.form
        )

        db.session.add(new_role)
        db.session.commit()

        flash('Role added successfully', 'success')
        return redirect(url_for('admin_roles'))

    return render_template('admin/add_role.html')


@app.route('/admin/edit_role/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_role(id):
    role = Role.query.get_or_404(id)

    if request.method == 'POST':
        role.name = request.form['name']

        # Update permissions
        role.can_view_complaints = 'can_view_complaints' in request.form
        role.can_manage_complaints = 'can_manage_complaints' in request.form
        role.can_view_issues = 'can_view_issues' in request.form
        role.can_manage_issues = 'can_manage_issues' in request.form
        role.can_view_repairs = 'can_view_repairs' in request.form
        role.can_manage_repairs = 'can_manage_repairs' in request.form
        role.can_view_replacements = 'can_view_replacements' in request.form
        role.can_manage_replacements = 'can_manage_replacements' in request.form
        role.is_admin = 'is_admin' in request.form
        role.can_manage_users = 'can_manage_users' in request.form

        db.session.commit()
        flash('Role updated successfully', 'success')
        return redirect(url_for('admin_roles'))

    return render_template('admin/edit_role.html', role=role)


@app.route('/admin/delete_role/<int:id>')
@login_required
@admin_required
def admin_delete_role(id):
    role = Role.query.get_or_404(id)

    # Check if role has users
    if role.users:
        flash('Cannot delete role with existing users', 'danger')
        return redirect(url_for('admin_roles'))

    db.session.delete(role)
    db.session.commit()

    flash('Role deleted successfully', 'success')
    return redirect(url_for('admin_roles'))


@app.route('/admin/complaints')
@login_required
@admin_required
def admin_complaints():
    complaints = Complaint.query.all()
    return render_template('admin/complaints.html', complaints=complaints)


@app.route('/admin/repairs')
@login_required
@admin_required
def admin_repairs():
    repairs = Repair.query.all()
    return render_template('admin/repairs.html', repairs=repairs)


@app.route('/admin/replacements')
@login_required
@admin_required
def admin_replacements():
    replacements = Replacement.query.all()
    return render_template('admin/replacements.html', replacements=replacements)


# Function to create default roles and a default company
def create_default_data():

    admin_user = User.query.filter_by(email='admin@example.com').first()
    if not admin_user:

        # Create account types first
        create_account_types()

        # Check if default company exists
        default_company = Company.query.filter_by(name="Default Company").first()
        if not default_company:
            # Get standard account type
            standard_account = AccountType.query.filter_by(name="Standard Account").first()

            default_company = Company(
                name="Default Company",
                account_type_id=standard_account.id if standard_account else 1
            )
            db.session.add(default_company)
            db.session.commit()
            print("Default company created")

        # Create default roles if they don't exist
        roles = {
            "Admin": {
                "can_view_complaints": True,
                "can_manage_complaints": True,
                "can_view_issues": True,
                "can_manage_issues": True,
                "can_view_repairs": True,
                "can_manage_repairs": True,
                "can_view_replacements": True,
                "can_manage_replacements": True,
                "can_view_bookings": True,
                "can_manage_bookings": True,
                "is_admin": True,
                "can_manage_users": True
            },
            "Manager": {
                "can_view_complaints": True,
                "can_manage_complaints": True,
                "can_view_issues": True,
                "can_manage_issues": True,
                "can_view_repairs": True,
                "can_manage_repairs": True,
                "can_view_replacements": True,
                "can_manage_replacements": True,
                "can_view_bookings": True,
                "can_manage_bookings": True,
                "is_admin": False,
                "can_manage_users": False
            },
            "Technician": {
                "can_view_complaints": True,
                "can_manage_complaints": False,
                "can_view_repairs": True,
                "can_manage_repairs": True,
                "can_view_replacements": False,
                "can_manage_replacements": False,
                "is_admin": False,
                "can_manage_users": False
            },
            "Cleaner": {
                "can_view_complaints": False,
                "can_manage_complaints": False,
                "can_view_repairs": False,
                "can_manage_repairs": False,
                "can_view_replacements": True,
                "can_manage_replacements": True,
                "is_admin": False,
                "can_manage_users": False
            }
        }

        for role_name, permissions in roles.items():
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name, **permissions)
                db.session.add(role)
                db.session.commit()
                print(f"Role '{role_name}' created")

        # Create admin user if no admin exists
        admin_role = Role.query.filter_by(name="Admin").first()
        admin = User.query.filter_by(is_admin=True).first()

        if not admin and admin_role:
            password = 'admin123'  # Default password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            admin = User(
                name='Admin',
                email='admin@example.com',
                password=hashed_password,
                role_id=admin_role.id,
                company_id=default_company.id
            )
            db.session.add(admin)
            db.session.commit()
            print('Admin user created with email: admin@example.com and password: admin123')

        # Create a few sample units for the default company
        if Unit.query.count() == 0:
            sample_units = [
                {"unit_number": "A-101", "building": "Block A", "floor": 1, "description": "Corner unit",
                 "is_occupied": True},
                {"unit_number": "A-102", "building": "Block A", "floor": 1, "description": "Middle unit",
                 "is_occupied": True},
                {"unit_number": "B-201", "building": "Block B", "floor": 2, "description": "End unit", "is_occupied": True},
                {"unit_number": "C-301", "building": "Block C", "floor": 3, "description": "Penthouse",
                 "is_occupied": False},
            ]

            for unit_data in sample_units:
                unit = Unit(
                    unit_number=unit_data["unit_number"],
                    building=unit_data["building"],
                    floor=unit_data["floor"],
                    description=unit_data["description"],
                    is_occupied=unit_data["is_occupied"],
                    company_id=default_company.id
                )
                db.session.add(unit)

            db.session.commit()
            print("Default data created successfully")
        else:
            print("Default data already exists")

    # Call the create_issue_defaults function
    create_issue_defaults()

    # Add the create_cleaner_role function definition here
    def create_cleaner_role():
        # Check if Cleaner role exists
        cleaner_role = Role.query.filter_by(name="Cleaner").first()
        if not cleaner_role:
            cleaner_role = Role(
                name="Cleaner",
                can_view_complaints=True,
                can_manage_complaints=False,
                can_view_issues=True,
                can_manage_issues=False,
                can_view_repairs=False,
                can_manage_repairs=False,
                can_view_replacements=False,
                can_manage_replacements=False,
                is_admin=False,
                can_manage_users=False
            )
            db.session.add(cleaner_role)
            db.session.commit()
            print("Cleaner role created")

    # Call the function at the end of create_default_data
    create_cleaner_role()


def create_account_types():
    # Check if account types exist
    if AccountType.query.count() == 0:
        account_types = [
            {"name": "Standard Account", "max_units": 20},
            {"name": "Premium Account", "max_units": 40},
            {"name": "Pro Account", "max_units": 80},
            {"name": "Elite Account", "max_units": 160},
            {"name": "Ultimate Account", "max_units": 2000}
        ]

        for type_data in account_types:
            account_type = AccountType(
                name=type_data["name"],
                max_units=type_data["max_units"]
            )
            db.session.add(account_type)

        db.session.commit()
        print("Account types created")


def create_issue_items():
    # Define issue items by category
    issue_items_by_category = {
        "Building Issue": [
            "Carpark - Not Enough",
            "Carpark - Too High",
            "Lift - Waiting too long",
            "Swimming pool",
            "Noisy neighbour"
        ],
        "Cleaning Issue": [
            "Dusty",
            "Bedsheet - Not Clean",
            "Bedsheet - Smelly",
            "Toilet - Smelly",
            "Toilet Not Clean",
            "House - Smelly",
            "Got Ants",
            "Got Cockroach",
            "Got Insects",
            "Got mouse",
            "Not enough towels",
            "Not enough toiletries"
        ],
        "Plumbing Issues": [
            "Basin stucked",
            "Basin dripping",
            "Faucet Dripping",
            "Bidet dripping",
            "Toilet bowl stuck",
            "Shower head",
            "Toilet fitting lose",
            "Water pressure Low",
            "Drainage problem"
        ],
        "Electrical Issue": [
            "TV Box",
            "Internet WiFi",
            "Water Heater",
            "Fan",
            "Washing machine",
            "House No Electric",
            "Light",
            "Hair dryer",
            "Iron",
            "Microwave",
            "Kettle",
            "Remote control",
            "Induction Cooker",
            "Rice Cooker",
            "Water Filter",
            "Fridge"
        ],
        "Furniture Issue": [
            "Chair",
            "Sofa",
            "Wardrobe",
            "Kitchenware",
            "Bed",
            "Pillow",
            "Bedframe",
            "Iron board Cover",
            "Windows",
            "Coffee Table",
            "Cabinet",
            "Dining Table"
        ],
        "Check-in Issue": [
            "Access card Holder",
            "Access card",
            "key",
            "Letterbox - cant open",
            "Letterbox - left open",
            "Letterbox - missing",
            "Door",
            "Door Password"
        ],
        "Aircond Issue": [
            "AC not cold",
            "AC leaking",
            "AC noisy",
            "AC empty - tank"
        ]
    }

    # Get or create categories
    for category_name, items in issue_items_by_category.items():
        # Get or create the category
        category = Category.query.filter_by(name=category_name).first()
        if not category:
            category = Category(name=category_name)
            db.session.add(category)
            db.session.flush()  # Flush to get the category ID

        # Create issue items for this category
        for item_name in items:
            # Check if the issue item already exists
            existing_item = IssueItem.query.filter_by(name=item_name, category_id=category.id).first()
            if not existing_item:
                issue_item = IssueItem(name=item_name, category_id=category.id)
                db.session.add(issue_item)

    db.session.commit()
    print("Issue items created successfully")


def create_issue_defaults():
    # Create categories
    categories = ["Building Issue", "Cleaning Issue", "Plumbing Issues", "Electrical Issue", "Furniture Issue",
                  "Check-in Issue", "Aircond Issue"]
    for category_name in categories:
        if not Category.query.filter_by(name=category_name).first():
            category = Category(name=category_name)
            db.session.add(category)

    # Create reported by options
    reporters = ["Cleaner", "Guest", "Operator", "Head"]
    for reporter_name in reporters:
        if not ReportedBy.query.filter_by(name=reporter_name).first():
            reporter = ReportedBy(name=reporter_name)
            db.session.add(reporter)

    # Create priorities
    priorities = ["High", "Medium", "Low"]
    for priority_name in priorities:
        if not Priority.query.filter_by(name=priority_name).first():
            priority = Priority(name=priority_name)
            db.session.add(priority)

    # Create statuses
    statuses = ["Pending", "In Progress", "Resolved", "Rejected"]
    for status_name in statuses:
        if not Status.query.filter_by(name=status_name).first():
            status = Status(name=status_name)
            db.session.add(status)

    # Create types
    types = ["Repair", "Replace"]
    for type_name in types:
        if not Type.query.filter_by(name=type_name).first():
            type_obj = Type(name=type_name)
            db.session.add(type_obj)

    db.session.commit()

    # Create the issue items
    create_issue_items()
    print("Issue defaults created")


@app.route('/bookings')
@login_required
@permission_required('can_view_bookings')
def bookings():
    # Filter records to only show those belonging to the user's company
    user_company_id = current_user.company_id
    bookings_list = BookingForm.query.filter_by(company_id=user_company_id).all()

    # Get units for this company for the form
    units = Unit.query.filter_by(company_id=user_company_id).all()

    # Calculate analytics for the dashboard
    today = datetime.now().date()
    tomorrow = today + timedelta(days=1)  # Get tomorrow's date

    # Calculate total units
    unit_total = Unit.query.filter_by(company_id=user_company_id).count()

    # Calculate occupancy today (units where check-in <= today < check-out)
    occupancy_current = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date <= today,
        BookingForm.check_out_date > today
    ).count()

    # Calculate check-ins today
    check_ins_today = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date == today
    ).count()

    # Calculate revenue today (total price of bookings with check-in today)
    today_check_ins = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date == today
    ).all()
    revenue_today = sum(float(booking.price) for booking in today_check_ins if booking.price)

    # Currently staying (check-in <= today < check-out)
    currently_staying = occupancy_current

    # Calculate check-ins tomorrow (NEW)
    check_ins_tomorrow = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date == tomorrow
    ).count()

    # Calculate check-outs today (NEW)
    check_outs_today = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_out_date == today
    ).count()

    # Calculate check-outs tomorrow (NEW)
    check_outs_tomorrow = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_out_date == tomorrow
    ).count()

    # Create stats dictionary
    stats = {
        'unit_total': unit_total,
        'occupancy_current': occupancy_current,
        'check_ins_today': check_ins_today,
        'revenue_today': '{:,.2f}'.format(revenue_today),
        'currently_staying': currently_staying,
        'check_ins_tomorrow': check_ins_tomorrow,  # New stat
        'check_outs_today': check_outs_today,  # New stat
        'check_outs_tomorrow': check_outs_tomorrow
    }

    return render_template('bookings.html', bookings=bookings_list, units=units, stats=stats, active_filter=None)


@app.route('/add_booking', methods=['GET', 'POST'])
@login_required
@permission_required('can_manage_bookings')
def add_booking():
    if request.method == 'POST':
        guest_name = request.form['guest_name']
        contact_number = request.form['contact_number']
        check_in_date = datetime.strptime(request.form['check_in_date'], '%Y-%m-%d').date()
        check_out_date = datetime.strptime(request.form['check_out_date'], '%Y-%m-%d').date()
        property_name = request.form['property_name']
        unit_id = request.form['unit_id']
        number_of_nights = (check_out_date - check_in_date).days
        number_of_guests = request.form['number_of_guests']
        price = request.form['price']
        booking_source = request.form['booking_source']
        payment_status = request.form['payment_status']
        notes = request.form['notes']

        # Get the unit
        unit = Unit.query.get(unit_id)
        if not unit:
            flash('Invalid unit selected', 'danger')
            return redirect(url_for('add_booking'))

        # Check if the unit belongs to the user's company
        if unit.company_id != current_user.company_id:
            flash('You do not have permission to book this unit', 'danger')
            return redirect(url_for('add_booking'))

        new_booking = BookingForm(
            guest_name=guest_name,
            contact_number=contact_number,
            check_in_date=check_in_date,
            check_out_date=check_out_date,
            property_name=property_name,
            unit_id=unit_id,
            number_of_nights=number_of_nights,
            number_of_guests=number_of_guests,
            price=price,
            booking_source=booking_source,
            payment_status=payment_status,
            notes=notes,
            company_id=current_user.company_id,
            user_id=current_user.id
        )

        db.session.add(new_booking)
        db.session.commit()

        flash('Booking added successfully', 'success')
        return redirect(url_for('bookings'))

    # Get units for the form
    units = Unit.query.filter_by(company_id=current_user.company_id).all()

    return render_template('booking_form.html', units=units)

@app.route('/delete_booking/<int:id>')
@login_required
@permission_required('can_manage_bookings')
def delete_booking(id):
    booking = BookingForm.query.get_or_404(id)

    # Ensure the current user's company matches the booking's company
    if booking.company_id != current_user.company_id:
        flash('You are not authorized to delete this booking', 'danger')
        return redirect(url_for('bookings'))

    db.session.delete(booking)
    db.session.commit()

    flash('Booking deleted successfully', 'success')
    return redirect(url_for('bookings'))


@app.route('/api/booking/<int:id>')
@login_required
@permission_required('can_view_bookings')
def get_booking(id):
    booking = BookingForm.query.get_or_404(id)

    # Ensure the current user's company matches the booking's company
    if booking.company_id != current_user.company_id:
        return jsonify({'error': 'Not authorized'}), 403

    return jsonify({
        'id': booking.id,
        'guest_name': booking.guest_name,
        'contact_number': booking.contact_number,
        'check_in_date': booking.check_in_date.strftime('%Y-%m-%d'),
        'check_out_date': booking.check_out_date.strftime('%Y-%m-%d'),
        'property_name': booking.property_name,
        'unit_id': booking.unit_id,
        'number_of_nights': booking.number_of_nights,
        'number_of_guests': booking.number_of_guests,
        'price': float(booking.price) if booking.price else 0,
        'booking_source': booking.booking_source,
        'payment_status': booking.payment_status,
        'notes': booking.notes
    })


@app.route('/update_booking/<int:id>', methods=['POST'])
@login_required
@permission_required('can_manage_bookings')
def update_booking(id):
    booking = BookingForm.query.get_or_404(id)

    # Ensure the current user's company matches the booking's company
    if booking.company_id != current_user.company_id:
        flash('You are not authorized to update this booking', 'danger')
        return redirect(url_for('bookings'))

    # Update fields
    booking.guest_name = request.form.get('guest_name', '')
    booking.contact_number = request.form.get('contact_number', '')

    check_in_date = datetime.strptime(request.form['check_in_date'], '%Y-%m-%d').date()
    check_out_date = datetime.strptime(request.form['check_out_date'], '%Y-%m-%d').date()

    booking.check_in_date = check_in_date
    booking.check_out_date = check_out_date
    booking.number_of_nights = (check_out_date - check_in_date).days

    booking.property_name = request.form.get('property_name', '')
    booking.unit_id = request.form['unit_id']
    booking.number_of_guests = request.form['number_of_guests']
    booking.price = request.form['price']
    booking.booking_source = request.form['booking_source']
    booking.payment_status = request.form.get('payment_status', 'Pending')
    booking.notes = request.form.get('notes', '')

    db.session.commit()
    flash('Booking updated successfully', 'success')
    return redirect(url_for('bookings'))


@app.route('/bookings/<filter_type>')
@login_required
@permission_required('can_view_bookings')
def bookings_filter(filter_type):
    # Filter records to only show those belonging to the user's company
    user_company_id = current_user.company_id

    # Get units for this company for the form
    units = Unit.query.filter_by(company_id=user_company_id).all()

    # Calculate analytics for the dashboard
    today = datetime.now().date()
    tomorrow = today + timedelta(days=1)

    # Calculate all the stats (same as in regular bookings route)
    unit_total = Unit.query.filter_by(company_id=user_company_id).count()

    occupancy_current = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date <= today,
        BookingForm.check_out_date > today
    ).count()

    check_ins_today = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date == today
    ).count()

    today_check_ins = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date == today
    ).all()
    revenue_today = sum(float(booking.price) for booking in today_check_ins if booking.price)

    currently_staying = occupancy_current

    check_ins_tomorrow = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_in_date == tomorrow
    ).count()

    check_outs_today = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_out_date == today
    ).count()

    check_outs_tomorrow = BookingForm.query.filter(
        BookingForm.company_id == user_company_id,
        BookingForm.check_out_date == tomorrow
    ).count()

    # Apply specific filter based on filter_type
    if filter_type == 'occupancy_current':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_in_date <= today,
            BookingForm.check_out_date > today
        ).all()
        filter_message = "Showing currently occupied units"
    elif filter_type == 'check_ins_today':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_in_date == today
        ).all()
        filter_message = f"Showing check-ins for today ({today.strftime('%b %d, %Y')})"
    elif filter_type == 'revenue_today':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_in_date == today
        ).all()
        filter_message = f"Showing revenue for today ({today.strftime('%b %d, %Y')})"
    elif filter_type == 'currently_staying':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_in_date <= today,
            BookingForm.check_out_date > today
        ).all()
        filter_message = "Showing currently staying guests"
    elif filter_type == 'check_ins_tomorrow':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_in_date == tomorrow
        ).all()
        filter_message = f"Showing check-ins for tomorrow ({tomorrow.strftime('%b %d, %Y')})"
    elif filter_type == 'check_outs_today':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_out_date == today
        ).all()
        filter_message = f"Showing check-outs for today ({today.strftime('%b %d, %Y')})"
    elif filter_type == 'check_outs_tomorrow':
        bookings_list = BookingForm.query.filter(
            BookingForm.company_id == user_company_id,
            BookingForm.check_out_date == tomorrow
        ).all()
        filter_message = f"Showing check-outs for tomorrow ({tomorrow.strftime('%b %d, %Y')})"
    else:
        # Default - show all bookings
        bookings_list = BookingForm.query.filter_by(company_id=user_company_id).all()
        filter_message = None

    # Create stats dictionary
    stats = {
        'unit_total': unit_total,
        'occupancy_current': occupancy_current,
        'check_ins_today': check_ins_today,
        'revenue_today': '{:,.2f}'.format(revenue_today),
        'currently_staying': currently_staying,
        'check_ins_tomorrow': check_ins_tomorrow,
        'check_outs_today': check_outs_today,
        'check_outs_tomorrow': check_outs_tomorrow
    }

    return render_template('bookings.html',
                           bookings=bookings_list,
                           units=units,
                           stats=stats,
                           filter_message=filter_message,
                           active_filter=filter_type)  # Pass the active filter to highlight the current selection


# Route for managers to view cleaners
@app.route('/manage_cleaners')
@login_required
def manage_cleaners():
    # Check if user is a manager - we'll use the Manager role
    manager_role = Role.query.filter_by(name="Manager").first()
    if not current_user.role_id == manager_role.id and not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Get all cleaners from the current user's company
    company_id = current_user.company_id
    cleaners = User.query.filter_by(company_id=company_id, is_cleaner=True).all()

    return render_template('manage_cleaners.html', cleaners=cleaners)


# Route for managers to update cleaner info
@app.route('/update_cleaner/<int:id>', methods=['GET', 'POST'])
@login_required
def update_cleaner(id):
    # Check if user is a manager
    manager_role = Role.query.filter_by(name="Manager").first()
    if not current_user.role_id == manager_role.id and not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Get the cleaner
    cleaner = User.query.get_or_404(id)

    # Make sure the cleaner belongs to the same company as the manager
    if cleaner.company_id != current_user.company_id:
        flash('You do not have permission to update this cleaner.', 'danger')
        return redirect(url_for('manage_cleaners'))

    # Get company units
    company_units = Unit.query.filter_by(company_id=current_user.company_id).all()

    if request.method == 'POST':
        # Update cleaner information
        cleaner.phone_number = request.form.get('phone_number', '')

        # Update assigned units
        # First, clear current assignments
        cleaner.assigned_units = []

        # Then add new assignments
        selected_units = request.form.getlist('assigned_units')
        for unit_id in selected_units:
            unit = Unit.query.get(unit_id)
            if unit and unit.company_id == current_user.company_id:
                cleaner.assigned_units.append(unit)

        db.session.commit()
        flash('Cleaner information updated successfully', 'success')
        return redirect(url_for('manage_cleaners'))

    return render_template('update_cleaner.html', cleaner=cleaner, units=company_units)


# Route for cleaner dashboard
@app.route('/cleaner_dashboard')
@login_required
def cleaner_dashboard():
    # Check if the user is a cleaner
    if not current_user.is_cleaner:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Get assigned units
    assigned_units = current_user.assigned_units

    # Get issues related to those units
    issues = []
    for unit in assigned_units:
        unit_issues = Issue.query.filter_by(unit_id=unit.id).all()
        issues.extend(unit_issues)

    # Sort issues by date, most recent first
    issues.sort(key=lambda x: x.date_added, reverse=True)

    return render_template('cleaner_dashboard.html', units=assigned_units, issues=issues)


# Add these routes to app.py

@app.route('/cleaning-schedule')
@login_required
def cleaning_schedule():
    # Only cleaners and managers can access this page
    if not current_user.is_cleaner and current_user.role.name != 'Manager' and not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    tomorrow = datetime.now().date() + timedelta(days=1)

    # Get tomorrow's checkouts and check-ins
    checkouts_tomorrow = BookingForm.query.filter(
        BookingForm.check_out_date == tomorrow
    ).all()

    checkins_tomorrow = BookingForm.query.filter(
        BookingForm.check_in_date == tomorrow
    ).all()

    # Map unit_id to checkin booking for fast lookups
    checkin_map = {booking.unit_id: booking for booking in checkins_tomorrow}

    # For managers, show all cleaners' schedules
    if current_user.role.name == 'Manager' or current_user.is_admin:
        cleaners = User.query.filter_by(company_id=current_user.company_id, is_cleaner=True).all()

        cleaner_schedules = []
        for cleaner in cleaners:
            # Get units assigned to this cleaner that have checkouts tomorrow
            assigned_units = cleaner.assigned_units
            cleaner_checkouts = []

            for unit in assigned_units:
                for checkout in checkouts_tomorrow:
                    if checkout.unit_id == unit.id:
                        # Check if there's a check-in tomorrow for this unit
                        has_checkin = unit.id in checkin_map
                        checkin_booking = checkin_map.get(unit.id)

                        # Calculate supplies based on whether there's a check-in tomorrow
                        if has_checkin:
                            towels = checkin_booking.number_of_guests
                            rubbish_bags = checkin_booking.number_of_nights
                            toilet_rolls = checkin_booking.number_of_nights * (unit.toilet_count or 1)
                        else:
                            towels = unit.towel_count or 2
                            rubbish_bags = 2
                            toilet_rolls = 2 * (unit.toilet_count or 1)

                        cleaner_checkouts.append({
                            'unit': unit,
                            'checkout': checkout,
                            'has_checkin': has_checkin,
                            'checkin_booking': checkin_booking,
                            'towels': towels,
                            'rubbish_bags': rubbish_bags,
                            'toilet_rolls': toilet_rolls
                        })

            if cleaner_checkouts:
                cleaner_schedules.append({
                    'cleaner': cleaner,
                    'checkouts': cleaner_checkouts
                })

        return render_template('cleaning_schedule_manager.html',
                               cleaner_schedules=cleaner_schedules,
                               tomorrow=tomorrow)

    # For cleaners, show only their assigned units
    else:
        assigned_units = current_user.assigned_units
        my_checkouts = []

        for unit in assigned_units:
            for checkout in checkouts_tomorrow:
                if checkout.unit_id == unit.id:
                    # Check if there's a check-in tomorrow for this unit
                    has_checkin = unit.id in checkin_map
                    checkin_booking = checkin_map.get(unit.id)

                    # Calculate supplies based on whether there's a check-in tomorrow
                    if has_checkin:
                        towels = checkin_booking.number_of_guests
                        rubbish_bags = checkin_booking.number_of_nights
                        toilet_rolls = checkin_booking.number_of_nights * (unit.toilet_count or 1)
                    else:
                        towels = unit.towel_count or 2
                        rubbish_bags = 2
                        toilet_rolls = 2 * (unit.toilet_count or 1)

                    my_checkouts.append({
                        'unit': unit,
                        'checkout': checkout,
                        'has_checkin': has_checkin,
                        'checkin_booking': checkin_booking,
                        'towels': towels,
                        'rubbish_bags': rubbish_bags,
                        'toilet_rolls': toilet_rolls
                    })

        return render_template('cleaning_schedule.html',
                               checkouts=my_checkouts,
                               tomorrow=tomorrow)


# Add these routes to your app.py file

from flask import jsonify, request
from datetime import datetime, timedelta
from sqlalchemy import func
import json


# Main analytics page route
@app.route('/analytics')
@login_required
def analytics():
    # Get data for filters
    categories = Category.query.all()
    priorities = Priority.query.all()
    statuses = Status.query.all()

    return render_template('analytics_reporting.html',
                           categories=categories,
                           priorities=priorities,
                           statuses=statuses)


# Add or update this route in app.py

@app.route('/api/analytics/issues')
@login_required
def get_analytics_issues():
    # Filter for current user's company
    company_id = current_user.company_id

    # Get filter parameters
    days = request.args.get('days', type=int)
    time_filter = request.args.get('time_filter')  # New parameter for special time filters
    category_id = request.args.get('category_id', type=int)
    priority_id = request.args.get('priority_id', type=int)
    status_id = request.args.get('status_id', type=int)
    view_type = request.args.get('view_type')  # New parameter: 'hourly' or 'monthly'

    # Start with base query for issues in user's company
    query = Issue.query.filter_by(company_id=company_id)

    # Apply date filter with calendar-based logic
    if days:
        # Standard days-based filtering
        date_threshold = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Issue.date_added >= date_threshold)
    elif time_filter:
        # Special time filters
        now = datetime.utcnow()
        malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')
        now_local = now.replace(tzinfo=pytz.utc).astimezone(malaysia_tz)

        if time_filter == 'hour':
            # Last 1 hour
            hour_ago = now - timedelta(hours=1)
            query = query.filter(Issue.date_added >= hour_ago)

        elif time_filter == 'today':
            # Today (00:00:00 to now)
            today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
            today_start_utc = today_start.astimezone(pytz.utc)
            query = query.filter(Issue.date_added >= today_start_utc)

        elif time_filter == 'yesterday':
            # Yesterday (00:00:00 to 23:59:59)
            yesterday_start = (now_local - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            yesterday_end = yesterday_start.replace(hour=23, minute=59, second=59, microsecond=999999)
            yesterday_start_utc = yesterday_start.astimezone(pytz.utc)
            yesterday_end_utc = yesterday_end.astimezone(pytz.utc)
            query = query.filter(Issue.date_added >= yesterday_start_utc, Issue.date_added <= yesterday_end_utc)

    # Apply other filters if specified
    if category_id:
        query = query.filter_by(category_id=category_id)

    if priority_id:
        query = query.filter_by(priority_id=priority_id)

    if status_id:
        query = query.filter_by(status_id=status_id)

    # Execute query
    issues = query.all()

    # Convert to serializable format with related data
    result = []
    for issue in issues:
        issue_data = {
            'id': issue.id,
            'description': issue.description,
            'unit': issue.unit,
            'date_added': issue.date_added.isoformat(),
            'solution': issue.solution,
            'guest_name': issue.guest_name,
            'cost': float(issue.cost) if issue.cost else None,
            'assigned_to': issue.assigned_to,

            # Include related data
            'category_id': issue.category_id,
            'category_name': issue.category.name if issue.category else None,

            'reported_by_id': issue.reported_by_id,
            'reported_by_name': issue.reported_by.name if issue.reported_by else None,

            'priority_id': issue.priority_id,
            'priority_name': issue.priority.name if issue.priority else None,

            'status_id': issue.status_id,
            'status_name': issue.status.name if issue.status else None,

            'type_id': issue.type_id,
            'type_name': issue.type.name if issue.type else None,

            'issue_item_id': issue.issue_item_id,
            'issue_item_name': issue.issue_item.name if issue.issue_item else None,
        }
        result.append(issue_data)

    return jsonify(result)


# API endpoint to get summary statistics
@app.route('/api/analytics/summary')
@login_required
def get_analytics_summary():
    company_id = current_user.company_id

    # Get total issues count
    total_issues = Issue.query.filter_by(company_id=company_id).count()

    # Get open issues count (Pending or In Progress)
    pending_status = Status.query.filter_by(name='Pending').first()
    in_progress_status = Status.query.filter_by(name='In Progress').first()

    open_issues_filter = []
    if pending_status:
        open_issues_filter.append(Issue.status_id == pending_status.id)
    if in_progress_status:
        open_issues_filter.append(Issue.status_id == in_progress_status.id)

    open_issues = 0
    if open_issues_filter:
        open_issues = Issue.query.filter_by(company_id=company_id).filter(db.or_(*open_issues_filter)).count()

    # Get resolved issues count
    resolved_status = Status.query.filter_by(name='Resolved').first()
    resolved_issues = 0
    if resolved_status:
        resolved_issues = Issue.query.filter_by(company_id=company_id, status_id=resolved_status.id).count()

    # Calculate average cost
    avg_cost_result = db.session.query(func.avg(Issue.cost)).filter(
        Issue.company_id == company_id,
        Issue.cost.isnot(None)
    ).scalar()
    avg_cost = float(avg_cost_result) if avg_cost_result else 0

    # Get top issue categories
    category_counts = db.session.query(
        Category.name,
        func.count(Issue.id).label('count')
    ).join(
        Issue, Issue.category_id == Category.id
    ).filter(
        Issue.company_id == company_id
    ).group_by(
        Category.name
    ).order_by(
        func.count(Issue.id).desc()
    ).limit(5).all()

    top_categories = [{'name': name, 'count': count} for name, count in category_counts]

    # Return JSON summary
    return jsonify({
        'total_issues': total_issues,
        'open_issues': open_issues,
        'resolved_issues': resolved_issues,
        'avg_cost': avg_cost,
        'top_categories': top_categories
    })


# Create the database tables
with app.app_context():
    db.create_all()
    create_default_data()
    create_account_types()

#if __name__ == '__main__':
#    app.run(debug=True)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


# AccountType model
class AccountType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    max_units = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"AccountType('{self.name}', max_units={self.max_units})"


# Company model
class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    account_type_id = db.Column(db.Integer, db.ForeignKey('account_type.id'), default=1)
    account_type = db.relationship('AccountType', backref='companies')
    users = db.relationship('User', backref='company', lazy=True)

    def __repr__(self):
        return f"Company('{self.name}')"


# Role model
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    # Role permissions
    can_view_complaints = db.Column(db.Boolean, default=False)
    can_manage_complaints = db.Column(db.Boolean, default=False)

    can_view_issues = db.Column(db.Boolean, default=False)
    can_manage_issues = db.Column(db.Boolean, default=False)

    can_view_repairs = db.Column(db.Boolean, default=False)
    can_manage_repairs = db.Column(db.Boolean, default=False)

    can_view_replacements = db.Column(db.Boolean, default=False)
    can_manage_replacements = db.Column(db.Boolean, default=False)

    can_view_bookings = db.Column(db.Boolean, default=False)
    can_manage_bookings = db.Column(db.Boolean, default=False)

    # Admin permissions
    is_admin = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)

    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f"Role('{self.name}')"


# Create a many-to-many relationship between cleaners and units
cleaner_units = db.Table('cleaner_units',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('unit_id', db.Integer, db.ForeignKey('unit.id'), primary_key=True)
)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    account_type_id = db.Column(db.Integer, db.ForeignKey('account_type.id'), nullable=False, default=1)
    account_type = db.relationship('AccountType', backref='users')

    # Foreign keys for company and role
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    is_cleaner = db.Column(db.Boolean, default=False)

    # Relationships
    complaints = db.relationship('Complaint', backref='author', lazy=True)
    issues = db.relationship('Issue', backref='author', lazy=True)
    repairs = db.relationship('Repair', backref='author', lazy=True)
    replacements = db.relationship('Replacement', backref='author', lazy=True)
    assigned_units = db.relationship('Unit', secondary=cleaner_units,
                                     backref=db.backref('assigned_cleaners', lazy='dynamic'))
    @property
    def is_admin(self):
        return self.role.is_admin

    def has_permission(self, permission):
        return getattr(self.role, permission, False)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}', '{self.company.name}', '{self.role.name}')"


class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unit_number = db.Column(db.String(20), nullable=False)  # Remove unique=True here
    description = db.Column(db.String(200))
    floor = db.Column(db.Integer)  # Optional field for floor number
    building = db.Column(db.String(100))  # Optional field for building name/number
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    is_occupied = db.Column(db.Boolean, default=True)
    toilet_count = db.Column(db.Integer, nullable=True)
    towel_count = db.Column(db.Integer, nullable=True)
    max_pax = db.Column(db.Integer, nullable=True)

    # Relationships
    company = db.relationship('Company', backref='units')
    complaints = db.relationship('Complaint', backref='unit_details', lazy=True)
    repairs = db.relationship('Repair', backref='unit_details', lazy=True)
    replacements = db.relationship('Replacement', backref='unit_details', lazy=True)

    # Add a composite unique constraint for unit_number and company_id
    __table_args__ = (db.UniqueConstraint('unit_number', 'company_id', name='_unit_company_uc'),)

    def __repr__(self):
        return f"Unit('{self.unit_number}', Building: '{self.building}', Floor: {self.floor})"


# New models for Issue functionality
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"Category('{self.name}')"


class ReportedBy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"ReportedBy('{self.name}')"


class Priority(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"Priority('{self.name}')"


class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"Status('{self.name}')"


class Type(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"Type('{self.name}')"


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(100), nullable=False)
    remark = db.Column(db.String(200))
    unit = db.Column(db.String(20), nullable=False)  # Keep for backward compatibility
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'))
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)

    company = db.relationship('Company', backref='complaints')

    def __repr__(self):
        return f"Complaint('{self.item}', '{self.unit}')"


class IssueItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))

    # Relationship to Category
    category = db.relationship('Category', backref='issue_items')

    def __repr__(self):
        return f"IssueItem('{self.name}')"


class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    unit = db.Column(db.String(20), nullable=False)  # Keep for backward compatibility
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'))
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # New fields
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    reported_by_id = db.Column(db.Integer, db.ForeignKey('reported_by.id'), nullable=True)
    priority_id = db.Column(db.Integer, db.ForeignKey('priority.id'), nullable=True)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=True)
    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=True)
    issue_item_id = db.Column(db.Integer, db.ForeignKey('issue_item.id'), nullable=True)  # New field
    solution = db.Column(db.Text, nullable=True)
    guest_name = db.Column(db.String(100), nullable=True)
    cost = db.Column(db.Numeric(10, 2), nullable=True)
    assigned_to = db.Column(db.String(100), nullable=True)

    # Original fields
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)

    # Relationships
    category = db.relationship('Category', backref='issues')
    reported_by = db.relationship('ReportedBy', backref='issues')
    priority = db.relationship('Priority', backref='issues')
    status = db.relationship('Status', backref='issues')
    type = db.relationship('Type', backref='issues')
    issue_item = db.relationship('IssueItem', backref='issues')  # New relationship
    company = db.relationship('Company', backref='issues')

    def __repr__(self):
        return f"Issue('{self.description}', '{self.unit}')"


class Repair(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(100), nullable=False)
    remark = db.Column(db.String(200))
    unit = db.Column(db.String(20), nullable=False)  # Keep for backward compatibility
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'))
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)

    company = db.relationship('Company', backref='repairs')

    def __repr__(self):
        return f"Repair('{self.item}', '{self.unit}', '{self.status}')"


class Replacement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(100), nullable=False)
    remark = db.Column(db.String(200))
    unit = db.Column(db.String(20), nullable=False)  # Keep for backward compatibility
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'))
    date_requested = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)

    company = db.relationship('Company', backref='replacements')

    def __repr__(self):
        return f"Replacement('{self.item}', '{self.unit}', '{self.status}')"


class BookingForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guest_name = db.Column(db.String(100), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    check_in_date = db.Column(db.Date, nullable=False)
    check_out_date = db.Column(db.Date, nullable=False)
    property_name = db.Column(db.String(100), nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'), nullable=False)
    unit = db.relationship('Unit', backref='bookings')
    number_of_nights = db.Column(db.Integer, nullable=False)
    number_of_guests = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    booking_source = db.Column(db.String(50), nullable=False)
    payment_status = db.Column(db.String(50), nullable=False, default='Pending')
    notes = db.Column(db.Text, nullable=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    company = db.relationship('Company', backref='bookings')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='bookings')
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Booking('{self.guest_name}', '{self.unit.unit_number}', Check-in: '{self.check_in_date}')"
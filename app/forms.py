"""WTForms definitions – every form uses CSRF (enforced globally by Flask-WTF)."""
import re
from flask_wtf   import FlaskForm
from wtforms     import (StringField, PasswordField, BooleanField, TextAreaField,
                          SelectField, FloatField, IntegerField, SubmitField)
from wtforms.validators import (DataRequired, Email, Length, EqualTo,
                                 NumberRange, Optional, ValidationError)


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginForm(FlaskForm):
    username = StringField("Username",  validators=[DataRequired(), Length(3, 80)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Keep me signed in")
    submit   = SubmitField("Sign In")


class RegistrationForm(FlaskForm):
    username = StringField("Username",  validators=[DataRequired(), Length(3, 80)])
    email    = StringField("Email",     validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(12, 128)])
    confirm  = PasswordField("Confirm Password",
                             validators=[DataRequired(),
                                         EqualTo("password", message="Passwords must match.")])
    # Public registration is restricted to the least-privileged role.
    # Manager/admin roles must be provisioned through a trusted admin process.
    role     = SelectField("Role", choices=[("analyst", "Analyst")], default="analyst")
    submit   = SubmitField("Create Account")

    def validate_username(self, field):
        if not re.match(r"^[a-zA-Z0-9_.\-]{3,80}$", field.data):
            raise ValidationError("Only letters, numbers, _, . and - are allowed.")

    def validate_password(self, field):
        p = field.data
        missing = []
        if not re.search(r"[A-Z]", p): missing.append("uppercase")
        if not re.search(r"[a-z]", p): missing.append("lowercase")
        if not re.search(r"\d",    p): missing.append("digit")
        if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', p):
            missing.append("special character")
        if missing:
            raise ValidationError("Password must include: " + ", ".join(missing) + ".")


class ChangePasswordForm(FlaskForm):
    current  = PasswordField("Current Password", validators=[DataRequired()])
    password = PasswordField("New Password",      validators=[DataRequired(), Length(12, 128)])
    confirm  = PasswordField("Confirm New Password",
                             validators=[DataRequired(), EqualTo("password")])
    submit   = SubmitField("Update Password")

    def validate_password(self, field):
        p = field.data
        missing = []
        if not re.search(r"[A-Z]", p): missing.append("uppercase")
        if not re.search(r"[a-z]", p): missing.append("lowercase")
        if not re.search(r"\d",    p): missing.append("digit")
        if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', p):
            missing.append("special character")
        if missing:
            raise ValidationError("Password must include: " + ", ".join(missing) + ".")


# ── Project ───────────────────────────────────────────────────────────────────

from app.models.project import Project

class ProjectForm(FlaskForm):
    name        = StringField("Project Name",  validators=[DataRequired(), Length(2, 200)])
    description = TextAreaField("Description", validators=[Optional(), Length(max=2000)])
    phase       = SelectField("SDLC Phase",    choices=[(p, p) for p in Project.PHASES])
    status      = SelectField("Status",        choices=[(s, s) for s in Project.STATUSES])
    submit      = SubmitField("Save Project")


# ── Risk Assessment ───────────────────────────────────────────────────────────

class RiskForm(FlaskForm):
    title       = StringField("Risk Title",          validators=[DataRequired(), Length(2, 200)])
    description = TextAreaField("Description",        validators=[Optional(), Length(max=3000)])
    likelihood  = IntegerField("Likelihood (1–5)",    validators=[DataRequired(), NumberRange(1, 5)])
    impact      = IntegerField("Impact (1–5)",         validators=[DataRequired(), NumberRange(1, 5)])
    mitigation  = TextAreaField("Mitigation Strategy",validators=[Optional(), Length(max=3000)])
    status      = SelectField("Status",
                              choices=[("Open","Open"),("Mitigated","Mitigated"),
                                       ("Accepted","Accepted"),("Closed","Closed")])
    submit      = SubmitField("Save Risk")


# ── Threat Model ──────────────────────────────────────────────────────────────

from app.models.threat import ThreatModel

class ThreatForm(FlaskForm):
    threat_name    = StringField("Threat Name",    validators=[DataRequired(), Length(2, 200)])
    stride_cat     = SelectField("STRIDE Category", choices=[(s, s) for s in ThreatModel.STRIDE])
    description    = TextAreaField("Description",   validators=[Optional(), Length(max=3000)])
    countermeasure = TextAreaField("Countermeasure",validators=[Optional(), Length(max=3000)])
    priority       = SelectField("Priority",
                                 choices=[(p, p) for p in ThreatModel.PRIORITIES])
    status         = SelectField("Status",
                                 choices=[(s, s) for s in ThreatModel.STATUSES])
    submit         = SubmitField("Save Threat")


# ── Security Finding ──────────────────────────────────────────────────────────

from app.models.finding import SecurityFinding

class FindingForm(FlaskForm):
    title       = StringField("Finding Title",  validators=[DataRequired(), Length(2, 200)])
    description = TextAreaField("Description",  validators=[Optional(), Length(max=4000)])
    severity    = SelectField("Severity",
                              choices=[(s, s) for s in SecurityFinding.SEVERITIES])
    cwe_id      = StringField("CWE ID",         validators=[Optional(), Length(max=20)])
    cvss_score  = FloatField("CVSS Score (0–10)",validators=[Optional(), NumberRange(0.0, 10.0)])
    remediation = TextAreaField("Remediation",  validators=[Optional(), Length(max=4000)])
    status      = SelectField("Status",
                              choices=[(s, s) for s in SecurityFinding.STATUSES])
    submit      = SubmitField("Save Finding")

    def validate_cwe_id(self, field):
        if field.data and not re.match(r"^CWE-\d{1,6}$", field.data):
            raise ValidationError("Format: CWE-NNN  (e.g. CWE-79)")

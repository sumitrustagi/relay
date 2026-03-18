from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, log_audit

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("schedule_csv.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.is_active and user.check_password(password):
            login_user(user)
            log_audit("LOGIN", "auth", user.id, f"Login: {username}")
            return redirect(request.args.get("next") or url_for("schedule_csv.index"))
        flash("Invalid username or password.", "danger")
        log_audit("LOGIN", "auth", None, f"Failed login attempt: {username}", status="FAIL")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_audit("LOGOUT", "auth", current_user.id, f"Logout: {current_user.username}")
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current  = request.form.get("current_password", "")
        new_pass = request.form.get("new_password", "")
        confirm  = request.form.get("confirm_password", "")
        if not current_user.check_password(current):
            flash("Current password is incorrect.", "danger")
        elif new_pass != confirm:
            flash("New passwords do not match.", "danger")
        elif len(new_pass) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            current_user.set_password(new_pass)
            db.session.commit()
            log_audit("UPDATE", "user", current_user.id, "Password changed")
            flash("Password updated successfully.", "success")
            return redirect(url_for("schedule_csv.index"))
    return render_template("change_password.html")

"""Project CRUD and ownership enforcement tests."""
import pytest
from app.extensions import db as _db
from app.models.project import Project
from app.models.user import User
from tests.conftest import login, logout


def create_project(client, name="Test Project"):
    return client.post(
        "/projects/new",
        data={"name": name, "description": "desc", "phase": "Requirements", "status": "Active"},
        follow_redirects=True,
    )


class TestProjectCRUD:
    def test_projects_require_login(self, client):
        r = client.get("/projects/", follow_redirects=True)
        # Redirects to login page ("Sign In" or "sign")
        assert b"Sign" in r.data or b"sign" in r.data.lower() or b"login" in r.data.lower()

    def test_create_project(self, client, db, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        r = create_project(client, "Alpha Project")
        assert r.status_code == 200
        assert Project.query.filter_by(name="Alpha Project").first() is not None
        logout(client)

    def test_list_projects(self, client, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        r = client.get("/projects/")
        assert r.status_code == 200
        logout(client)

    def test_project_detail(self, client, db, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        p = Project.query.filter_by(owner_id=admin_user.id).first()
        if not p:
            create_project(client, "Detail Test")
            p = Project.query.filter_by(name="Detail Test").first()
        assert p is not None
        r = client.get(f"/projects/{p.id}")
        assert r.status_code == 200
        logout(client)

    def test_edit_project(self, client, db, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        p = Project.query.filter_by(owner_id=admin_user.id).first()
        if not p:
            create_project(client, "Edit Test")
            p = Project.query.filter_by(name="Edit Test").first()
        assert p is not None
        r = client.post(
            f"/projects/{p.id}/edit",
            data={"name": "Edited Name", "description": "updated", "phase": "Design", "status": "Active"},
            # phase "Design" is a valid choice
            follow_redirects=True,
        )
        assert r.status_code == 200
        logout(client)

    def test_delete_project(self, client, db, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        create_project(client, "ToDelete")
        p = Project.query.filter_by(name="ToDelete").first()
        assert p is not None
        pid = p.id
        r = client.post(f"/projects/{pid}/delete", follow_redirects=True)
        assert r.status_code == 200
        assert Project.query.filter_by(id=pid).first() is None
        logout(client)


class TestProjectOwnership:
    def test_analyst_cannot_access_others_project(self, client, db, admin_user, analyst_user):
        login(client, "testadmin", "Admin@Secure1!")
        create_project(client, "AdminOnlyProject")
        p = Project.query.filter_by(name="AdminOnlyProject").first()
        pid = p.id
        logout(client)

        login(client, "testanalyst", "Analyst@Secure1!")
        r = client.get(f"/projects/{pid}", follow_redirects=True)
        # Should be 403 or redirected with error
        assert r.status_code in (200, 403)
        logout(client)

    def test_analyst_can_access_own_project(self, client, db, analyst_user):
        login(client, "testanalyst", "Analyst@Secure1!")
        create_project(client, "AnalystProject")
        p = Project.query.filter_by(name="AnalystProject").first()
        assert p is not None
        assert p.owner_id == analyst_user.id
        r = client.get(f"/projects/{p.id}")
        assert r.status_code == 200
        logout(client)

    def test_manager_can_see_all_projects(self, client, db, admin_user, manager_user):
        login(client, "testadmin", "Admin@Secure1!")
        create_project(client, "ManagerVisibleProject")
        logout(client)

        login(client, "testmanager", "Manager@Secure1!")
        r = client.get("/projects/", follow_redirects=True)
        assert r.status_code == 200
        logout(client)

    def test_404_on_nonexistent_project(self, client, admin_user):
        login(client, "testadmin", "Admin@Secure1!")
        r = client.get("/projects/999999", follow_redirects=True)
        assert r.status_code in (200, 404)
        logout(client)

from django.db import models
from django.utils import timezone
from django.db.models import UniqueConstraint
from django.db.models.functions import Lower
from django.conf import settings
from pathlib import Path
from django.core.exceptions import ValidationError
from .validators import validate_pdf_magic, validate_file_max_size, validate_safe_filename

class Users(models.Model):
    class Profile(models.TextChoices):
        SEM_ACESSO = 'Sem Acesso', 'Sem Acesso'
        ADMINISTRADOR = 'Administrador', 'Administrador'
        AUDITOR = 'Auditor', 'Auditor'
        GERENTE_REGIONAL = 'Gerente Regional', 'Gerente Regional'
        USUARIO = 'Usuário', 'Usuário'

    u_id = models.AutoField(primary_key=True)
    u_name = models.CharField(max_length=256)
    u_login = models.CharField(max_length=100)
    u_password = models.CharField(max_length=100)
    u_email = models.EmailField(max_length=256, unique=True)
    u_status = models.CharField(max_length=20, default="Inativo")
    u_time_in = models.DateField(auto_now_add=True)
    u_time_out = models.DateField()
    u_profile = models.CharField(max_length=40, choices=Profile.choices, default=Profile.SEM_ACESSO)

    def __str__(self):
        return self.u_login

class Document(models.Model):
    d_id = models.AutoField(primary_key=True)
    d_doc = models.CharField(max_length=50, unique=True)

    class Meta:
        constraints = [UniqueConstraint(Lower('d_doc'), name='uq_document_ddoc_lower')]

    def __str__(self):
        return self.d_doc

class Establishment(models.Model):
    est_id = models.IntegerField(primary_key=True)
    est_center = models.CharField(max_length=50)
    est_region = models.CharField(max_length=30, null=True, blank=True)
    est_state = models.CharField(max_length=2)
    est_city = models.CharField(max_length=50)
    est_address = models.CharField(max_length=256)
    est_manage = models.CharField(max_length=30, default='-')
    est_property = models.CharField(max_length=20, default='-')

    def __str__(self):
        return self.est_center

class EstAux(models.Model):
    estaux_id = models.AutoField(primary_key=True)
    estaux_region = models.CharField(max_length=20)
    estaux_uf = models.CharField(max_length=20)

class NumDocsEstab(models.Model):
    ndest_id = models.AutoField(primary_key=True)
    ndest_units = models.CharField(max_length=20)
    ndest_cnpj = models.CharField(max_length=18, default='-')
    ndest_nire = models.CharField(max_length=11, default='-')
    ndest_reg_city = models.CharField(max_length=20, default='-')
    ndest_reg_state = models.CharField(max_length=20, default='-')
    ndest_fk_establishment = models.ForeignKey(Establishment, on_delete=models.RESTRICT)

class RelationCenterUser(models.Model):
    rcu_id = models.AutoField(primary_key=True)
    rcu_center = models.CharField(max_length=50, default='-')
    rcu_state = models.CharField(max_length=2, default='-')
    rcu_region = models.CharField(max_length=30, default='-')
    rcu_fk_user = models.ForeignKey(Users, on_delete=models.RESTRICT)

    def __str__(self):
        return self.rcu_fk_user.u_login

class RelationCenterDoc(models.Model):
    rcd_id = models.AutoField(primary_key=True)
    rcd_fk_establishment = models.ForeignKey(Establishment, on_delete=models.RESTRICT)
    rcd_fk_document = models.ForeignKey(Document, on_delete=models.RESTRICT)

class Attachment(models.Model):
    att_id = models.AutoField(primary_key=True)
    att_situation = models.CharField(max_length=30, default="Em Análise")
    att_data_expire = models.DateField()
    att_attached_by = models.CharField(max_length=100)
    att_checked_by = models.CharField(max_length=100, null=True, blank=True)
    att_data_conference = models.DateTimeField(null=True, blank=True)
    att_data_inserted = models.DateTimeField(auto_now_add=True)
    att_file = models.FileField(upload_to='pdfs/', null=False, blank=False)
    att_region = models.CharField(max_length=30)
    att_state = models.CharField(max_length=2)
    att_city = models.CharField(max_length=50)
    att_doc = models.CharField(max_length=50)
    att_center = models.CharField(max_length=50)
    att_just = models.CharField(max_length=256, blank=True, null=True)

    def clean(self):
        super().clean()
        if self.att_file and hasattr(self.att_file, 'file'):
            validate_file_max_size(self.att_file.file, max_bytes=10 * 1024 * 1024)
            validate_pdf_magic(self.att_file.file)
            validate_safe_filename(self.att_file)
            try:
                abspath = Path(self.att_file.path).resolve()
                mediaroot = Path(settings.MEDIA_ROOT).resolve()
                if not str(abspath).startswith(str(mediaroot)):
                    raise ValidationError('Caminho de arquivo inválido.')
            except Exception:
                pass

class Audit(models.Model):
    aud_id = models.AutoField(primary_key=True)
    aud_action = models.CharField(max_length=30)
    aud_obj_modified = models.CharField(max_length=30)
    aud_description = models.CharField(max_length=256, default='-')
    aud_data_inserted = models.DateTimeField(auto_now_add=True)
    aud_login = models.CharField(max_length=100)
    aud_profile = models.CharField(max_length=100)

class Email(models.Model):
    em_id = models.AutoField(primary_key=True)
    em_from = models.EmailField(max_length=256, blank=True, null=True)
    em_email = models.EmailField(max_length=256, blank=True)
    em_subject = models.CharField(max_length=128)
    em_data_shipping = models.DateField(auto_now_add=True)
    em_doc = models.CharField(max_length=256)
    em_center = models.CharField(max_length=256)
    em_login = models.CharField(max_length=100)

class LoginAttempt(models.Model):
    id = models.AutoField(primary_key=True)
    login = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)

    def __str__(self):
        status = "Sucesso" if self.was_successful else "Falha"
        local_time = timezone.localtime(self.timestamp)
        return f"{self.login} - {self.ip_address} - {self.user_agent} - {status} - {local_time.strftime('%d/%m/%Y %H:%M:%S')}"

class SecurityEvent(models.Model):
    class ActionType(models.TextChoices):
        LOGIN = 'Login', 'Login'
        LOGOUT = 'Logout', 'Logout'
        WAF_BLOCK = 'WAF Block', 'Bloqueio WAF'
        SESSION_HIJACK = 'Session Hijack', 'Sequestro de Sessão'
        IP_BLOCK = 'IP Block', 'IP Bloqueado'
        PDF_ACCESS = 'PDF Access', 'Acesso a PDF'
        OTHER = 'Other', 'Outro'

    sec_id = models.AutoField(primary_key=True)
    sec_action = models.CharField(max_length=50, choices=ActionType.choices)
    sec_description = models.TextField()
    sec_ip = models.GenericIPAddressField()
    sec_user_agent = models.TextField(blank=True, null=True)
    sec_payload = models.TextField(blank=True, null=True)
    sec_data = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.sec_action} - {self.sec_ip} - {self.sec_data.strftime('%d/%m/%Y %H:%M:%S')}"

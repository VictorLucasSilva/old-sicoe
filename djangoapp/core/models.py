from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    u_status = models.CharField(max_length=7, default="Inativo")
    u_time_in = models.DateField(auto_now_add=True)
    u_time_out = models.DateField(null=True, blank=True)
    u_num_employee = models.IntegerField(null=True)

class Establishment(models.Model):
    est_id = models.IntegerField(primary_key=True)
    est_center = models.CharField(max_length=100, null=True, blank=False)
    est_city = models.CharField(max_length=50, null=True, blank=False)
    est_state = models.CharField(max_length=2, null=True, blank=False)
    est_cep = models.CharField(max_length=9, null=True, blank=False)
    est_sigla = models.CharField(max_length=30, null=True, blank=False)
    est_region = models.CharField(max_length=30, null=True, blank=True)
    est_address = models.CharField(max_length=512, null=True, blank=False)
    est_manage = models.CharField(max_length=30, null=True, default='-') 
    est_property = models.CharField(max_length=20, null=True, default='-')

    def __str__(self):
        return self.est_center

class rs_q_emp(models.Model):
    rs_q_id = models.AutoField(primary_key=True)
    rs_q_email = models.EmailField(max_length=256, null=True)
    rs_q_name = models.CharField(max_length=128, null=True)
    rs_q_uor = models.CharField(max_length=20, null=True)
    rs_q_sigla_uor = models.CharField(max_length=128, null=True)
    rs_q_depen_uor = models.CharField(max_length=20, null=True)
    rs_q_depen_sigla_uor = models.CharField(max_length=128, null=True)
    rs_q_emplid = models.IntegerField(null=True)
    rs_q_estabid = models.IntegerField(null=True)

class Document(models.Model):
    d_id = models.AutoField(primary_key=True) 
    d_doc = models.CharField(max_length=50, null=False, unique=True) 

    def __str__(self):
        return self.d_doc

class EstAux(models.Model):
    estaux_id = models.AutoField(primary_key=True)
    estaux_region = models.CharField(max_length=20, null=False, blank=False)
    estaux_uf = models.CharField(max_length=20, null=False, blank=False)

class NumDocsEstab(models.Model):
    ndest_id = models.AutoField(primary_key=True)
    ndest_units = models.CharField(max_length=20, null=False, blank=False)
    ndest_cnpj = models.CharField(max_length=18, default='-')
    ndest_nire = models.CharField(max_length=15, default='-', blank=True)  
    ndest_reg_city = models.CharField(max_length=20, default='-', blank=True)
    ndest_reg_state = models.CharField(max_length=20, default='-', blank=True)
    ndest_fk_establishment = models.ForeignKey(Establishment, on_delete=models.RESTRICT)

class RelationCenterUser(models.Model):
    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["rcu_fk_user", "rcu_fk_estab"],
                name="uniq_rcu_user_estab",
            )
        ]
    rcu_id = models.AutoField(primary_key=True)
    rcu_center = models.CharField(max_length=50, default='-')
    rcu_state = models.CharField(max_length=2, default='-')
    rcu_region = models.CharField(max_length=30, default='-')
    rcu_active = models.BooleanField(default=False, db_index=True)
    rcu_fk_user = models.ForeignKey(User, on_delete=models.RESTRICT)
    rcu_fk_estab = models.ForeignKey(Establishment, on_delete=models.RESTRICT)
    
    def __str__(self):
        return self.rcu_fk_user.first_name

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
    att_region = models.CharField(max_length=30, null=False, blank=False)
    att_state = models.CharField(max_length=2, null=False, blank=False) 
    att_city = models.CharField(max_length=50, null=False, blank=False)  
    att_doc = models.CharField(max_length=50, null=False, blank=False) 
    att_center = models.CharField(max_length=50, null=False, blank=False)
    att_just = models.CharField(max_length=512, blank=True, null=True)
    DOCUMENT_TYPES = [
        ('pdf', 'PDF')
    ]

class Audit(models.Model):
    aud_id = models.AutoField(primary_key=True)
    aud_action = models.CharField(max_length=30, blank=False, null=False)
    aud_obj_modified = models.CharField(max_length=30, blank=False, null=False)
    aud_description = models.CharField(max_length=256, default='-')
    aud_data_inserted = models.DateTimeField(auto_now_add=True)
    aud_login = models.CharField(max_length=100)
    aud_profile = models.CharField(max_length=100)

class Email(models.Model):
    em_id = models.AutoField(primary_key=True)
    em_from = models.EmailField(max_length=256, blank=True, null=True)
    em_email = models.EmailField(max_length=256, blank=True)
    em_subject = models.CharField(max_length=128, null=False, blank=False)
    em_data_shipping = models.DateField(auto_now_add=True)
    em_doc = models.CharField(max_length=256, null=False) 
    em_center = models.CharField(max_length=256, null=False, blank=False)
    em_login = models.CharField(max_length=100, null=False, blank=False)
    em_send_email = models.CharField(max_length=5, null=True, blank=True, default="false")

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

class PsFuncionario(models.Model):
    func_matricula = models.IntegerField(primary_key=True)
    func_nm_cargo = models.CharField(max_length=100, null=True, blank=False)
    func_nm_funcao = models.CharField(max_length=100, null=True, blank=False)
    func_nm_email = models.EmailField(max_length=254, null=True, blank=False)



import re
import unicodedata
from django import forms
from core.models import NumDocsEstab, User, RelationCenterDoc, Document, RelationCenterUser, Attachment, Establishment
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.db.models.functions import Lower
from datetime import date

SAFE_DOC_RE = re.compile(r"^[\w\sÀ-ÖØ-öø-ÿ\-\.,]{2,50}$", re.UNICODE)

class DCreateForm(forms.ModelForm): 
    class Meta:
        model = Document
        fields = ['d_doc']
        widgets = {
            'd_doc': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite o nome do documento',
                'autocomplete': 'off',
                'maxlength': '50'
            })
        }
        labels = {'d_doc': 'Nome do Documento'}

    clean_pattern = RegexValidator(
        regex=SAFE_DOC_RE,
        message='Use apenas letras, números, espaços e ",.-" (2 a 50 caracteres).'
    )

    def clean_d_doc(self):
        raw = (self.cleaned_data.get('d_doc') or '')
        norm = unicodedata.normalize('NFKC', raw).strip()
        norm = re.sub(r'\s+', ' ', norm)[:50] 
        if not norm:
            raise forms.ValidationError('O campo Documento é obrigatório.')
        self.clean_pattern(norm)
        title_norm = ' '.join(word.capitalize() for word in norm.split(' '))

        if Document.objects.filter(d_doc__iexact=title_norm).exists():
            raise forms.ValidationError('O Documento digitado já existe.')

        return title_norm
    
class AttachmentForm(forms.Form):
    region = forms.CharField(
        required=True,
        error_messages={'required': 'Por favor, selecione a região.'}
    )
    state = forms.CharField(
        required=True,
        error_messages={'required': 'Por favor, selecione o estado.'}
    )
    center = forms.CharField(
        required=True,
        error_messages={'required': 'Por favor, selecione o estabelecimento.'}
    )
    document = forms.CharField(
        required=True,
        error_messages={'required': 'Por favor, selecione o documento.'}
    )
    data_expire = forms.DateField(
        required=True,
        input_formats=['%d/%m/%Y', '%Y-%m-%d'], 
        error_messages={'required': 'Por favor, informe a data de vencimento.'}
    )
    file = forms.FileField(
        required=True,
        error_messages={'required': 'Por favor, selecione o arquivo PDF para anexar.'}
    )

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file.size > 5 * 1024 * 1024:
            raise ValidationError("Arquivo muito grande (máx 5MB).")
        if not file.name.lower().endswith('.pdf'):
            raise ValidationError("Somente arquivos PDF são permitidos.")
        return file

    def clean_data_expire(self):
        data_expire = self.cleaned_data.get('data_expire')
        if data_expire and data_expire < date.today():
            raise ValidationError("Data de vencimento não pode ser no passado.")
        return data_expire

    def clean_center(self):
        center_name = (self.cleaned_data.get('center') or '').strip()
        region = (self.cleaned_data.get('region') or '').strip()
        state = (self.cleaned_data.get('state') or '').strip()

        if not Establishment.objects.filter(
            est_center=center_name, est_region=region, est_state=state
        ).exists():
            raise ValidationError("Estabelecimento inválido.")
        return center_name

    def clean_document(self):
        doc = (self.cleaned_data.get('document') or '').strip()
        center_name = (self.cleaned_data.get('center') or '').strip()
        region = (self.cleaned_data.get('region') or '').strip()
        state = (self.cleaned_data.get('state') or '').strip()

        if not doc:
            raise ValidationError("Por favor, selecione o documento.")

        try:
            center_obj = Establishment.objects.get(
                est_center=center_name, est_region=region, est_state=state
            )
        except Establishment.DoesNotExist:
            raise ValidationError("Estabelecimento inválido.")

        allowed = RelationCenterDoc.objects.filter(
            rcd_fk_establishment=center_obj, rcd_fk_document__d_doc=doc
        ).exists()
        if not allowed:
            raise ValidationError("Documento não permitido para este estabelecimento.")

        last_for_doc = (Attachment.objects
                        .filter(att_center=center_obj.est_center, att_doc=doc)
                        .order_by('-att_data_inserted')
                        .first())
        if last_for_doc and last_for_doc.att_situation in ('Regular', 'Em Análise'):
            raise ValidationError(
                f"Já existe um anexo de '{doc}' com status '{last_for_doc.att_situation}' para este estabelecimento."
            )
        return doc

class NDESTCreateForm(forms.ModelForm):
    UNITS_CHOICES = [
        ("", "Selecione"),
        ("CAT", "CAT"),
        ("CECAN", "CECAN"),
        ("CEMAN", "CEMAN"),
        ("CEDOC", "CEDOC"),
        ("CESID", "CESID"),
        ("CEMOT", "CEMOT"),
        ("ESTOQUE CENTRAL", "ESTOQUE CENTRAL"),
        ("FILIAL", "FILIAL"),
        ("MATRIZ", "MATRIZ"),
        ("ARQUIVO GERAL", "ARQUIVO GERAL"),
    ]

    class Meta:
        model = NumDocsEstab
        fields = [
            "ndest_fk_establishment",
            "ndest_units",
            "ndest_cnpj",
            "ndest_nire",
            "ndest_reg_city",
            "ndest_reg_state",
        ]
        labels = {
            "ndest_fk_establishment": "Estabelecimento",
            "ndest_units": "Unidade",
            "ndest_cnpj": "CNPJ",
            "ndest_nire": "NIRE",
            "ndest_reg_city": "Inscrição Municipal",
            "ndest_reg_state": "Inscrição Estadual",
        }
        widgets = {
            "ndest_fk_establishment": forms.Select(attrs={"class": "form-select"}),
            "ndest_units": forms.Select(attrs={"class": "form-select"}),
            "ndest_cnpj": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "00.000.000/0000-00",
                "inputmode": "numeric",
                "autocomplete": "off",
                "maxlength": "18",
            }),
            "ndest_nire": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Digite o NIRE (opcional)",
                "inputmode": "numeric",
                "maxlength": "15",
            }),
            "ndest_reg_city": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Digite a inscrição municipal (opcional)",
                "inputmode": "numeric",
                "maxlength": "15",
            }),
            "ndest_reg_state": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "Digite a inscrição estadual (opcional)",
                "inputmode": "numeric",
                "maxlength": "15",
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["ndest_nire"].required = False
        self.fields["ndest_reg_city"].required = False
        self.fields["ndest_reg_state"].required = False
        self.fields["ndest_units"].choices = self.UNITS_CHOICES

    def clean_ndest_cnpj(self):
        cnpj_raw = (self.cleaned_data.get("ndest_cnpj") or "").strip()
        if not cnpj_raw:
            raise ValidationError("O campo CNPJ é obrigatório.")
        digits = re.sub(r"\D", "", cnpj_raw)
        if len(digits) != 14:
            raise ValidationError("O CNPJ deve conter 14 dígitos numéricos.")
        if not self.validar_cnpj(digits):
            raise ValidationError("CNPJ inválido.")
        return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:14]}"

    def clean_ndest_nire(self):
        nire = (self.cleaned_data.get("ndest_nire") or "").strip()
        if not nire:
            return "-"
        digits = re.sub(r"\D", "", nire)
        if len(digits) > 15:
            raise ValidationError("O NIRE deve conter no máximo 15 dígitos numéricos.")
        return digits

    def clean_ndest_reg_state(self):
        state = (self.cleaned_data.get("ndest_reg_state") or "").strip()
        if not state:
            return "-"
        digits = re.sub(r"\D", "", state)
        if len(digits) > 15:
            raise ValidationError("A Inscrição Estadual deve conter no máximo 15 dígitos numéricos.")
        return digits

    def clean_ndest_reg_city(self):
        city = (self.cleaned_data.get("ndest_reg_city") or "").strip()
        if not city:
            return "-"
        digits = re.sub(r"\D", "", city)
        if len(digits) > 15:
            raise ValidationError("A Inscrição Municipal deve conter no máximo 15 dígitos numéricos.")
        return digits

    def clean_ndest_units(self):
        unit = (self.cleaned_data.get("ndest_units") or "").strip()
        if not unit:
            raise ValidationError("O campo Unidade é obrigatório.")
        return unit.upper()

    def validar_cnpj(self, cnpj: str) -> bool:
        base = cnpj[:-2]
        dv = cnpj[-2:]
        peso1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        soma1 = sum(int(base[i]) * peso1[i] for i in range(12))
        r1 = soma1 % 11
        d1 = 0 if r1 < 2 else 11 - r1
        peso2 = [6] + peso1
        soma2 = sum(int(cnpj[i]) * peso2[i] for i in range(13))
        r2 = soma2 % 11
        d2 = 0 if r2 < 2 else 11 - r2
        return dv == f"{d1}{d2}"

class RCDCreateForm(forms.ModelForm):
    class Meta:
        model = RelationCenterDoc
        fields = ['rcd_fk_establishment', 'rcd_fk_document']
        widgets = {
            'rcd_fk_establishment': forms.Select(attrs={'class': 'form-control', 'id': 'center'}),
            'rcd_fk_document': forms.Select(attrs={'class': 'form-control', 'id': 'doc'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['rcd_fk_establishment'].queryset = Establishment.objects.order_by(Lower('est_center'), 'est_center')
        self.fields['rcd_fk_document'].queryset = Document.objects.order_by(Lower('d_doc'), 'd_doc')

    def clean_rcd_fk_establishment(self):
        est = self.cleaned_data.get('rcd_fk_establishment')
        if not est:
            raise forms.ValidationError('O campo Estabelecimento é obrigatório.')
        return est

    def clean_rcd_fk_document(self):
        doc = self.cleaned_data.get('rcd_fk_document')
        if not doc:
            raise forms.ValidationError('O campo Documento é obrigatório.')
        return doc

    def clean(self):
        data = super().clean()
        est = data.get('rcd_fk_establishment')
        doc = data.get('rcd_fk_document')
        if est and doc:
            from core.models import RelationCenterDoc
            if RelationCenterDoc.objects.filter(rcd_fk_establishment=est, rcd_fk_document=doc).exists():
                raise forms.ValidationError('Esta relação já existe.')
        return data

User = get_user_model()

class RCUCreateForm(forms.ModelForm):
    class Meta:
        model = RelationCenterUser
        fields = ["rcu_fk_user", "rcu_fk_estab"]
        labels = {"rcu_fk_user": "Colaborador", "rcu_fk_estab": "Estabelecimento"}
        widgets = {
            "rcu_fk_user": forms.Select(attrs={"class": "form-control", "id": "user"}),
            "rcu_fk_estab": forms.Select(attrs={"class": "form-control", "id": "center"}),
        }

    def __init__(self, *args, users_qs=None, centers_qs=None, selected_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if users_qs is None:
            users_qs = (
                User.objects.filter(is_active=True, u_status="Ativo", groups__name__in=["Usuário", "Gerente Regional"])
                .distinct().order_by("username")
            )
        self.fields["rcu_fk_user"].queryset = users_qs

        if centers_qs is None:
            centers_qs = Establishment.objects.order_by("est_center")

        # >>> Só use selected_user quando a view passar (GET). No POST a view não passa.
        if selected_user:
            ativos_ids = (
                RelationCenterUser.objects
                .filter(rcu_fk_user=selected_user, rcu_active=True)
                .values_list("rcu_fk_estab_id", flat=True)
            )
            centers_qs = centers_qs.exclude(pk__in=list(ativos_ids))

        self.fields["rcu_fk_estab"].queryset = centers_qs.order_by(Lower("est_center"), "est_center")

    def clean(self):
        data = super().clean()
        if not data.get("rcu_fk_user"):
            self.add_error("rcu_fk_user", "Selecione um colaborador.")
        if not data.get("rcu_fk_estab"):
            self.add_error("rcu_fk_estab", "Selecione um estabelecimento.")
        return data
    
class OverAttachmentForm(forms.Form):
    data_expire = forms.DateField(
        required=True,
        input_formats=['%d/%m/%Y', '%Y-%m-%d'],
        error_messages={'required': 'Por favor, informe a data de vencimento.'}
    )
    file = forms.FileField(
        required=True,
        error_messages={'required': 'Por favor, selecione o arquivo PDF para anexar.'}
    )

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_file(self):
        up = self.cleaned_data.get('file')
        if not up:
            raise ValidationError("Arquivo é obrigatório.")

        if up.size > 5 * 1024 * 1024:
            raise ValidationError("Arquivo muito grande (máx. 5MB).")

        name = (up.name or '').lower()
        if not name.endswith('.pdf'):
            raise ValidationError("Somente arquivos PDF são permitidos.")

        head = up.read(5)
        up.seek(0)
        if head != b'%PDF-':
            raise ValidationError("PDF inválido.")
        return up

    def clean_data_expire(self):
        d = self.cleaned_data.get('data_expire')
        if d and d < date.today():
            raise ValidationError("Data de vencimento não pode ser no passado.")
        return d 
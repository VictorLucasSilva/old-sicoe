from django import forms
from core.models import NumDocsEstab, Users, RelationCenterDoc, Document, RelationCenterUser, Attachment, Establishment
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from datetime import date
import re
from core.utils.fieldsec import (
    sanitize_for_form, waf_validate_text, ensure_regex,
    forbid_quotes_and_comments, smart_titlecase
)

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
                'maxlength': '50',
                'id': 'id_d_doc',
            })
        }
        labels = {'d_doc': 'Nome do Documento'}

    clean_pattern = RegexValidator(
        regex=SAFE_DOC_RE,
        message='Use apenas letras, números, espaços e ",.-" (2 a 50 caracteres).'
    )

    def clean_d_doc(self):
        raw = self.cleaned_data.get('d_doc') or ''
        val = sanitize_for_form(raw, max_len=50)

        if not val:
            raise forms.ValidationError('O campo Documento é obrigatório.')

        # WAF lógico (server-side) — bloqueia SQLi/XSS/template/encoding suspeitos
        waf_validate_text(val, block_noncrit_on_forms=True)

        # Bloqueia aspas/comentários e força regex permitida
        forbid_quotes_and_comments(val)
        ensure_regex(val, SAFE_DOC_RE, 'Use apenas letras, números, espaços e ",.-" (2 a 50 caracteres).')

        # Normalização consistente de exibição
        val = smart_titlecase(val)[:50]

        # Unicidade case-insensitive
        if Document.objects.filter(d_doc__iexact=val).exists():
            raise forms.ValidationError('O Documento digitado já existe.')

        return val
    
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
        center_name = self.cleaned_data.get('center')
        region = self.cleaned_data.get('region')
        state = self.cleaned_data.get('state')
        if not Establishment.objects.filter(est_center=center_name, est_region=region, est_state=state).exists():
            raise ValidationError("Estabelecimento inválido.")
        return center_name
    

class NDESTCreateForm(forms.ModelForm):
    class Meta:
        model = NumDocsEstab
        fields = [
            'ndest_fk_establishment',
            'ndest_units',
            'ndest_cnpj',
            'ndest_nire',
            'ndest_reg_city',
            'ndest_reg_state'
        ]
        labels = {
            'ndest_fk_establishment': 'Estabelecimento',
            'ndest_units': 'Unidade',
            'ndest_cnpj': 'CNPJ',
            'ndest_nire': 'NIRE',
            'ndest_reg_city': 'Inscrição Municipal',
            'ndest_reg_state': 'Inscrição Estadual'
        }
        widgets = {
            'ndest_fk_establishment': forms.Select(attrs={
                'class': 'form-control'
            }),
            'ndest_units': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite o nome da unidade'
            }),
            'ndest_cnpj': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite o CNPJ'
            }),
            'ndest_nire': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite o NIRE (opcional)'
            }),
            'ndest_reg_city': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite a inscrição municipal'
            }),
            'ndest_reg_state': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite a inscrição estadual'
            }),
        }

    def clean_ndest_fk_establishment(self):
        center = self.cleaned_data.get('ndest_fk_establishment')
        if not center:
            raise ValidationError('O campo Estabelecimento é obrigatório.')
        return center

    def clean_ndest_units(self):
        unit = self.cleaned_data.get('ndest_units', '').strip()
        if not unit:
            raise ValidationError('O campo Unidade é obrigatório.')
        return unit.upper()

    def clean_ndest_cnpj(self):
        cnpj = self.cleaned_data.get('ndest_cnpj', '').strip()
        if not cnpj:
            raise ValidationError('O campo CNPJ é obrigatório.')
        cnpj = re.sub(r'\D', '', cnpj)
        if len(cnpj) != 14:
            raise ValidationError('O CNPJ deve conter 14 dígitos numéricos.')
        if not self.validar_cnpj(cnpj):
            raise ValidationError('CNPJ inválido.')
        return cnpj

    def clean_ndest_nire(self):
        nire = self.cleaned_data.get('ndest_nire', '').strip()
        if nire and nire != '-' and len(nire) != 9:
            raise ValidationError('O NIRE, caso preenchido, deve ter 9 dígitos numéricos.')
        return nire

    def clean_ndest_reg_state(self):
        state = self.cleaned_data.get('ndest_reg_state', '').strip()
        if state:
            state = re.sub(r'\D', '', state)
            if len(state) != 9:
                raise ValidationError('A Inscrição Estadual deve conter 9 dígitos numéricos.')
        return state

    def clean_ndest_reg_city(self):
        city = self.cleaned_data.get('ndest_reg_city', '').strip()
        if city:
            city = re.sub(r'\D', '', city)
            if len(city) not in [8, 9]:
                raise ValidationError('A Inscrição Municipal deve ter 8 ou 9 dígitos numéricos.')
        return city

    def validar_cnpj(self, cnpj):
        """Valida CNPJ usando cálculo de dígitos verificadores."""
        cnpj_base = cnpj[:-2]
        digitos = cnpj[-2:]

        peso1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        soma1 = sum(int(cnpj_base[i]) * peso1[i] for i in range(12))
        resto1 = soma1 % 11
        digito1 = 0 if resto1 < 2 else 11 - resto1

        peso2 = [6] + peso1
        soma2 = sum(int(cnpj[i]) * peso2[i] for i in range(13))
        resto2 = soma2 % 11
        digito2 = 0 if resto2 < 2 else 11 - resto2

        return digitos == f"{digito1}{digito2}"
    

class RCDCreateForm(forms.ModelForm):
    class Meta:
        model = RelationCenterDoc
        fields = ['rcd_fk_establishment', 'rcd_fk_document']
        widgets = {
            'rcd_fk_establishment': forms.Select(attrs={'class': 'form-control'}),
            'rcd_fk_document': forms.Select(attrs={'class': 'form-control'}),
        }

    def clean_rcd_fk_establishment(self):
        establishment = self.cleaned_data.get('rcd_fk_establishment')
        if not establishment:
            raise forms.ValidationError('O campo Estabelecimento é obrigatório.')
        return establishment

    def clean_rcd_fk_document(self):
        document = self.cleaned_data.get('rcd_fk_document')
        if not document:
            raise forms.ValidationError('O campo Documento é obrigatório.')
        return document

class UCreateForm(forms.ModelForm):
    class Meta:
        model = Users
        fields = ['u_time_out', 'u_profile', 'u_status']
        widgets = {
            'u_time_out': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'u_profile': forms.Select(attrs={
                'class': 'form-control'
            }),
            'u_status': forms.Select(choices=[
                ('Ativo', 'Ativo'),
                ('Inativo', 'Inativo')
            ], attrs={
                'class': 'form-control'
            }),
        }

    def clean_u_time_out(self):
        time_out = self.cleaned_data.get('u_time_out')
        if not time_out:
            raise ValidationError('O campo Data de Saída é obrigatório.')
        if time_out < date.today():
            raise ValidationError('A Data de Saída não pode ser no passado.')
        return time_out

    def clean_u_profile(self):
        profile = self.cleaned_data.get('u_profile')
        if not profile:
            raise ValidationError('O campo Perfil é obrigatório.')
        return profile

    def clean_u_status(self):
        status = self.cleaned_data.get('u_status')
        if status not in ['Ativo', 'Inativo']:
            raise ValidationError('O Status deve ser Ativo ou Inativo.')
        return status
  
class RCUCreateForm(forms.ModelForm): 
    class Meta:
        model = RelationCenterUser
        fields = ['rcu_center', 'rcu_region', 'rcu_state', 'rcu_fk_user']
        widgets = {
            'rcu_center': forms.TextInput(attrs={'class': 'form-control'}),
            'rcu_region': forms.TextInput(attrs={'class': 'form-control'}),
            'rcu_state': forms.TextInput(attrs={'class': 'form-control'}),
            'rcu_fk_user': forms.TextInput(attrs={'class': 'form-control'})
        }

    def clean(self):
        cleaned_data = super().clean()
        center = cleaned_data.get('rcu_center')
        region = cleaned_data.get('rcu_region')
        state = cleaned_data.get('rcu_state')

        filled = [bool(center), bool(region), bool(state)]

        if sum(filled) == 0:
            raise forms.ValidationError("Preencha ao menos um campo entre Estabelecimento, Região ou Estado.")
        if sum(filled) > 1:
            raise forms.ValidationError("Preencha apenas um dos campos: Estabelecimento, Região ou Estado.")

        return cleaned_data

    def clean_rcu_fk_user(self):
        user = self.cleaned_data.get('rcu_fk_user')
        if not user or str(user).strip() == "":
            raise forms.ValidationError('O campo Usuário é obrigatório.')
        return user.strip().capitalize()
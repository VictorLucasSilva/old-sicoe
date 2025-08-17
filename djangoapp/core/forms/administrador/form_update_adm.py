import re

from django import forms
from core.models import NumDocsEstab, Establishment, Users, RelationCenterDoc, Document, RelationCenterUser, Attachment
from core.utils.fieldsec import (
    sanitize_for_form, waf_validate_text, ensure_regex,
    forbid_quotes_and_comments, smart_titlecase
)

SAFE_DOC_RE = re.compile(r"^[\w\sÀ-ÖØ-öø-ÿ\-\.,]{2,50}$", re.UNICODE)

class DUpdateForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['d_doc']
        widgets = {
            'd_doc': forms.TextInput(attrs={'class': 'form-control', 'maxlength': '50', 'id': 'id_d_doc'})
        }

    def clean_d_doc(self):
        raw = self.cleaned_data.get('d_doc') or ''
        val = sanitize_for_form(raw, max_len=50)

        if not val:
            raise forms.ValidationError('O campo Documento é obrigatório.')

        waf_validate_text(val, block_noncrit_on_forms=True)
        forbid_quotes_and_comments(val)
        ensure_regex(val, SAFE_DOC_RE, 'Use apenas letras, números, espaços e ",.-" (2 a 50 caracteres).')

        val = smart_titlecase(val)[:50]

        qs = Document.objects.filter(d_doc__iexact=val)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('O Documento digitado já existe.')

        return val

class EstUpdateForm(forms.ModelForm):
    class Meta:
        model = Establishment
        fields = ['est_manage', 'est_property']

    def clean_est_manage(self):
        
        manage = self.cleaned_data.get('est_manage')
        if not manage:
            raise forms.ValidationError('Se deseja deixar o campo sem valor coloque traço (-)')
        manage = str(manage).strip().capitalize()
        if len(manage) == 0:
            raise forms.ValidationError('Se deseja deixar o campo sem valor coloque traço (-)')
        if not re.match(r'^[A-Za-zÀ-ÖØ-öø-ÿ\s-]+$', manage):
            raise forms.ValidationError('O campo Área Gestora não pode conter números ou caracteres especiais.')
        return manage

    def clean_est_property(self):
        
        property = self.cleaned_data.get('est_property')
        if not property:
            raise forms.ValidationError('O campo Propriedade é obrigatório.')
        property = str(property).strip().capitalize()
        if len(property) == 0:
            raise forms.ValidationError('O campo Propriedade não pode ser vazio.')
        if not re.match(r'^[A-Za-zÀ-ÖØ-öø-ÿ\s-]+$', property):
            raise forms.ValidationError('O campo Propriedade não pode conter números ou caracteres especiais.')
        return property
    
    def __init__(self, *args, **kwargs):
        super(EstUpdateForm, self).__init__(*args, **kwargs)
        self.fields['est_manage'].required = False
        self.fields['est_property'].required = False
        
        self.fields['est_manage'].error_messages = {}
        self.fields['est_property'].error_messages = {}


class INVUpdateForm(forms.ModelForm):
    class Meta:
        model = Attachment
        fields = ['att_just']
        widgets = {
            'att_just': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Digite a justificativa'
            })
        }

    def clean_att_just(self):
        just = self.cleaned_data.get('att_just')
        if not just:
            raise forms.ValidationError('O campo Justificativa é obrigatório.')
        return just

class EXPUpdateForm(forms.ModelForm):
    class Meta:
        model = Attachment
        fields = ['att_data_expire']
        widgets = {
            'att_data_expire': forms.DateInput(
                attrs={
                    'class': 'form-control date-mask',
                    'placeholder': 'dd/mm/aaaa',
                },
                format='%d/%m/%Y'
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['att_data_expire'].input_formats = ['%d/%m/%Y']

    def clean_att_data_expire(self):
        expire = self.cleaned_data.get('att_data_expire')
        if not expire:
            raise forms.ValidationError('O campo Data de Expiração é obrigatório.')
        return expire


class CNPJUpdateForm(forms.ModelForm):
    class Meta:
        model = NumDocsEstab
        fields = ['ndest_fk_establishment', 'ndest_units', 'ndest_cnpj', 'ndest_nire', 'ndest_reg_state', 'ndest_reg_city']

    def clean_ndest_fk_establishment(self):
        establishment = self.cleaned_data.get('ndest_fk_establishment')
        if not establishment:
            raise forms.ValidationError('O campo Estabelecimento é obrigatório.')
        return establishment

    def clean_ndest_units(self):
        unit = self.cleaned_data.get('ndest_units')
        if not unit:
            raise forms.ValidationError('O campo Unidade é obrigatório.')
        unit = str(unit).strip().upper()
        if len(unit) == 0:
            raise forms.ValidationError('O campo Unidade não pode ser vazio.')
        return unit

    def clean_ndest_cnpj(self):
        cnpj = self.cleaned_data.get('ndest_cnpj')
        if not cnpj:
            raise forms.ValidationError('O campo CNPJ é obrigatório.')

        cnpj = re.sub(r'\D', '', cnpj)
        if len(cnpj) == 0:
            raise forms.ValidationError('O CNPJ deve conter 14 dígitos numéricos.')

        if not self.validar_cnpj(cnpj):
            raise forms.ValidationError('CNPJ inválido.')

        if NumDocsEstab.objects.filter(ndest_cnpj=cnpj).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError('O CNPJ digitado já existe.')

        return cnpj


    def clean_ndest_nire(self):
        nire = self.cleaned_data.get('ndest_nire')
        if nire and nire != '-' and len(nire) == 0:
            raise forms.ValidationError('O NIRE deve ter 9 dígitos numéricos.')
        if nire and NumDocsEstab.objects.filter(ndest_nire=nire).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError('O NIRE já existe.')
        return nire

    def clean_ndest_reg_state(self):
        state = self.cleaned_data.get('ndest_reg_state')
        if state:
            state = re.sub(r'\D', '', state)
            if len(state) == 0:
                raise forms.ValidationError('A IE deve conter 9 dígitos numéricos.')
            if NumDocsEstab.objects.filter(ndest_reg_state=state).exclude(pk=self.instance.pk).exists():
                raise forms.ValidationError('A IE já existe.')
        return state

    def clean_ndest_reg_city(self):
        city = self.cleaned_data.get('ndest_reg_city')
        if city:
            city = re.sub(r'\D', '', city)
            if len(city) not in [8,9]:
                raise forms.ValidationError('A IM deve ter 8 ou 9 dígitos numéricos.')
            if NumDocsEstab.objects.filter(ndest_reg_city=city).exclude(pk=self.instance.pk).exists():
                raise forms.ValidationError('A IM já existe.')
        return city

    def validar_cnpj(self, cnpj):
        if len(cnpj) != 0:
            return False

        cnpj_base = cnpj[:-2]
        digitos = cnpj[-2:]

        peso1 = [5,4,3,2,9,8,7,6,5,4,3,2]
        soma1 = sum(int(cnpj_base[i]) * peso1[i] for i in range(12))
        resto1 = soma1 % 11
        digito1 = 0 if resto1 < 2 else 11 - resto1

        peso2 = [6] + peso1
        soma2 = sum(int(cnpj_base[i]) * peso2[i] for i in range(13))
        resto2 = soma2 % 11
        digito2 = 0 if resto2 < 2 else 11 - resto2

        return digitos == f"{digito1}{digito2}"

class RCDUpdateForm(forms.ModelForm):
    class Meta:
        model = RelationCenterDoc
        fields = ['rcd_fk_establishment', 'rcd_fk_document']
        widgets = {
            'rcd_fk_establishment': forms.HiddenInput(),
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

class UUpdateForm(forms.ModelForm):
    class Meta:
        model = Users
        fields = ['u_time_out', 'u_profile', 'u_status']
        widgets = {
            'u_time_out': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'u_profile': forms.Select(attrs={'class': 'form-control'}),
            'u_status': forms.Select(choices=[('Ativo', 'Ativo'), ('Inativo', 'Inativo')], attrs={'class': 'form-control'}),
        }

    def clean_u_time_out(self):
        time_out = self.cleaned_data.get('u_time_out')
        if not time_out:
            raise forms.ValidationError('O campo Data de Saída é obrigatório.')
        return time_out

    def clean_u_profile(self):
        profile = self.cleaned_data.get('u_profile')
        if not profile:
            raise forms.ValidationError('O campo Perfil é obrigatório.')
        return profile

    def clean_u_status(self):
        status = self.cleaned_data.get('u_status')
        if not status:
            raise forms.ValidationError('O campo Status é obrigatório.')
        return status

class RCUUpdateForm(forms.ModelForm): 
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

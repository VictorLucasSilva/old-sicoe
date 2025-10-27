from django import forms
from core.models import NumDocsEstab, Establishment, User, RelationCenterDoc, Document, RelationCenterUser, Attachment
from django.contrib.auth.models import Group
from datetime import datetime
import re, unicodedata

class DUpdateForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['d_doc']
        widgets = {
            'd_doc': forms.TextInput(attrs={'class': 'form-control', 'maxlength': '50'})
        }

    def clean_d_doc(self):
        raw = self.cleaned_data.get('d_doc') or ''
        norm = unicodedata.normalize('NFKC', raw).strip()
        norm = re.sub(r'\s+', ' ', norm)[:50]

        if not norm:
            raise forms.ValidationError('O campo Documento é obrigatório.')

        title_norm = ' '.join(word.capitalize() for word in norm.split(' '))

        qs = Document.objects.filter(d_doc__iexact=title_norm)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('O Documento digitado já existe.')

        return title_norm

SIGLAS_GESTORAS = [
    "DIAGE","DIAPA","DIATI","DICIT","DICOA","DICOC","DICOF","DICOI","DICOM","DICON","DICOP","DICOR",
    "DICOS","DIDAP","DIDES","DIEMP","DIENG","DIFIN","DIFIT","DIGES","DIGOV","DIJUC","DIJUN","DIJUS",
    "DIJUT","DILIC","DIMAC","DIMAG","DIMUC","DINEL","DIOGE","DIPAR","DIPAV","DIPLI","DIPRA","DIPRO",
    "DIREL","DIREM","DIRIS","DISEC","DISEF","DISEI","DISEN","DISOP","DISUP","DITIC","DITOP","DITRI",
    "-"
]
ALLOWED_GESTORAS = {s.upper() for s in SIGLAS_GESTORAS} | {"-"}

class EstUpdateForm(forms.ModelForm):
    class Meta:
        model = Establishment
        fields = ['est_manage', 'est_property']

    def clean_est_manage(self):
        manage = (self.cleaned_data.get('est_manage') or '').strip().upper()
        if manage not in ALLOWED_GESTORAS:
            raise forms.ValidationError('Selecione uma opção válida da lista.')
        return manage

    def clean_est_property(self):
        prop = self.cleaned_data.get('est_property')
        if prop is None:
            raise forms.ValidationError('O campo Propriedade é obrigatório.')
        prop = str(prop).strip()
        if not prop:
            raise forms.ValidationError('O campo Propriedade não pode ser vazio.')
        if not re.match(r'^[A-Za-zÀ-ÖØ-öø-ÿ\s-]+$', prop):
            raise forms.ValidationError('O campo Propriedade não pode conter números ou caracteres especiais.')
        self.cleaned_data['est_property'] = prop.capitalize()
        return self.cleaned_data['est_property']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
                attrs={'class': 'form-control date-mask', 'placeholder': 'dd/mm/aaaa'},
                format='%d/%m/%Y'
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['att_data_expire'].input_formats = ['%Y-%m-%d', '%d/%m/%Y']

    def clean_att_data_expire(self):
        expire = self.cleaned_data.get('att_data_expire')
        if not expire:
            raise forms.ValidationError('O campo Data de Expiração é obrigatório.')
        return expire


class CNPJUpdateForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.require_establishment = kwargs.pop('require_establishment', True)
        super().__init__(*args, **kwargs)
        if not self.require_establishment:
            self.fields['ndest_fk_establishment'].required = False

    class Meta:
        model = NumDocsEstab
        fields = [
            'ndest_fk_establishment',
            'ndest_units',
            'ndest_cnpj',
            'ndest_nire',
            'ndest_reg_state',
            'ndest_reg_city',
        ]

    @staticmethod
    def _digits(value: str) -> str:
        return re.sub(r'\D', '', (value or ''))

    @staticmethod
    def _is_blank_like(value: str) -> bool:
        return value is None or str(value).strip() == '' or str(value).strip() == '-'

    @staticmethod
    def _fmt_cnpj_from_digits(d: str) -> str:
        if len(d) != 14:
            return d
        return f"{d[0:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:14]}"

    def clean_ndest_fk_establishment(self):
        est = self.cleaned_data.get('ndest_fk_establishment')
        if est:
            return est
        if not self.require_establishment and self.instance and self.instance.pk:
            return self.instance.ndest_fk_establishment
        raise forms.ValidationError('O campo Estabelecimento é obrigatório.')

    def clean_ndest_units(self):
        unit = (self.cleaned_data.get('ndest_units') or '').strip().upper()
        if not unit:
            raise forms.ValidationError('O campo Unidade é obrigatório.')
        return unit

    def clean_ndest_cnpj(self):
        raw = self.cleaned_data.get('ndest_cnpj')
        if not raw:
            raise forms.ValidationError('O campo CNPJ é obrigatório.')

        digits = self._digits(raw)
        if len(digits) != 14:
            raise forms.ValidationError('O CNPJ deve conter 14 dígitos numéricos.')
        if digits == digits[0] * 14:
            raise forms.ValidationError('CNPJ inválido.')

        base = digits[:-2]
        pesos1 = [5,4,3,2,9,8,7,6,5,4,3,2]
        d1s = sum(int(n)*p for n,p in zip(base, pesos1))
        d1 = 0 if (d1s % 11) < 2 else 11 - (d1s % 11)
        pesos2 = [6] + pesos1
        d2s = sum(int(n)*p for n,p in zip(base+str(d1), pesos2))
        d2 = 0 if (d2s % 11) < 2 else 11 - (d2s % 11)
        if not digits.endswith(f"{d1}{d2}"):
            raise forms.ValidationError('CNPJ inválido.')

        qs = NumDocsEstab.objects.all()
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        existing = qs.values_list('ndest_cnpj', flat=True)
        for c in existing:
            if self._digits(c) == digits:
                raise forms.ValidationError('O CNPJ digitado já existe.')
        return self._fmt_cnpj_from_digits(digits)

    def clean_ndest_nire(self):
        raw = self.cleaned_data.get('ndest_nire')
        if self._is_blank_like(raw):
            return '-'
        nire = self._digits(raw)
        if len(nire) != 9:
            raise forms.ValidationError('O NIRE deve ter 9 dígitos numéricos.')
        qs = NumDocsEstab.objects.filter(ndest_nire=nire)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('O NIRE já existe.')
        return nire

    def clean_ndest_reg_state(self):
        raw = self.cleaned_data.get('ndest_reg_state')
        if self._is_blank_like(raw):
            return '-'
        ie = self._digits(raw)
        if len(ie) != 9:
            raise forms.ValidationError('A IE deve conter 9 dígitos numéricos.')
        qs = NumDocsEstab.objects.filter(ndest_reg_state=ie)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('A IE já existe.')
        return ie

    def clean_ndest_reg_city(self):
        raw = self.cleaned_data.get('ndest_reg_city')
        if self._is_blank_like(raw):
            return '-'
        im = self._digits(raw)
        if len(im) not in (8, 9):
            raise forms.ValidationError('A IM deve ter 8 ou 9 dígitos numéricos.')
        qs = NumDocsEstab.objects.filter(ndest_reg_city=im)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('A IM já existe.')
        return im

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

def _parse_date_flex(value):
    if not value:
        return None
    if hasattr(value, "year") and hasattr(value, "month") and hasattr(value, "day"):
        return value
    v = str(value).strip()
    if re.fullmatch(r"\d{2}/\d{2}/\d{4}", v):
        return datetime.strptime(v, "%d/%m/%Y").date()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return datetime.strptime(v, "%Y-%m-%d").date()
    raise ValueError("invalid")

class UUpdateForm(forms.ModelForm):
    u_status = forms.ChoiceField(
        choices=(("Ativo","Ativo"), ("Inativo","Inativo")),
        label="Status"
    )
    u_time_out = forms.DateField(
        required=False,
        input_formats=["%d/%m/%Y", "%Y-%m-%d"],
        label="Data de Saída"
    )

    class Meta:
        model = User
        fields = ("u_status", "u_time_out")

class RCUUpdateForm(forms.ModelForm):
    class Meta:
        model = RelationCenterUser
        fields = ["rcu_fk_estab"]
        labels = {"rcu_fk_estab": "Estabelecimento"}
        widgets = {
            "rcu_fk_estab": forms.Select(attrs={"class": "form-control", "id": "center"}),
        }

    def __init__(self, *args, centers_qs=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["rcu_fk_estab"].queryset = (centers_qs or Establishment.objects.all()).order_by("est_center")

    def clean(self):
        cleaned = super().clean()
        est = cleaned.get("rcu_fk_estab")
        if not est:
            raise forms.ValidationError("Selecione o Estabelecimento.")
        u = self.instance.rcu_fk_user
        if RelationCenterUser.objects.exclude(pk=self.instance.pk).filter(rcu_fk_user=u, rcu_fk_estab=est).exists():
            raise forms.ValidationError("Já existe uma relação para este Usuário com este Estabelecimento.")
        return cleaned

    def save(self, commit=True):
        instance = super().save(commit=False)
        est = self.cleaned_data["rcu_fk_estab"]
        instance.rcu_center = est.est_center or "-"
        instance.rcu_region = est.est_region or "-"
        instance.rcu_state  = est.est_state  or "-"
        instance.rcu_active = True
        if commit:
            instance.save()
        return instance
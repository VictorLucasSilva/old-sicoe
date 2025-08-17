import re
from django import forms
from django.core.exceptions import ValidationError
from django.utils.html import escape

PROHIBITED_USERNAMES = {
    'admin', 'root', 'administrator', 'suporte', 'test', 'guest', 'sys', 'system'
}
WEAK_PASSWORDS = {
    '123456', '12345678', 'password', 'senha', 'admin', 'qwerty', 'abc123'
}
INVISIBLE_CHARS = r'[\u200B-\u200F\u202A-\u202E\x00-\x1F]'

def sanitize_and_validate(value: str, field_name: str, max_length=100) -> str:
    if not value:
        return ''
    value = re.sub(INVISIBLE_CHARS, '', value)
    value = value.strip()[:max_length]
    value = escape(value)

    sql_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(\bOR\b|\bAND\b).*(=|LIKE)",
        r"UNION\s+SELECT",
        r"INSERT\s+INTO",
        r"DROP\s+TABLE",
        r"UPDATE\s+.+SET",
        r"DELETE\s+FROM"
    ]
    for pattern in sql_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValidationError(f"O campo '{field_name}' contém conteúdo não permitido.")

    xss_patterns = [
        r"<script.*?>.*?</script.*?>",
        r"javascript\s*:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<img.*?>",
        r"<svg.*?>",
        r"<iframe.*?>",
        r"<object.*?>"
    ]
    for pattern in xss_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValidationError(f"O campo '{field_name}' contém código suspeito.")

    command_patterns = [
        r";", r"\|\|", r"\&\&", r"\.\./", r"~/"
    ]
    for pattern in command_patterns:
        if re.search(pattern, value):
            raise ValidationError(f"O campo '{field_name}' contém comandos não permitidos.")

    return value

class CustomLoginForm(forms.Form):
    login = forms.CharField(
        label='',
        widget=forms.TextInput(attrs={
            'placeholder': 'Usuário',
            'style': (
                'background-color: #f0f0f0; color: #000000; text-align: center; '
                'border-radius: 4px; padding: 5px; font-size: 16px; '
                'border: 1px solid #ddd; width: 100%;'
            )
        })
    )
    password = forms.CharField(
        label='',
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Senha',
            'style': (
                'background-color: #f0f0f0; color: #000000; text-align: center; '
                'border-radius: 4px; padding: 5px; font-size: 16px; '
                'border: 1px solid #ddd; width: 100%;'
            )
        })
    )

    def clean_login(self):
        value = self.cleaned_data.get('login', '')
        value = sanitize_and_validate(value, "login", 100)
        if value.lower() in PROHIBITED_USERNAMES:
            raise ValidationError("Este nome de usuário não é permitido.")
        return value

    def clean_password(self):
        value = self.cleaned_data.get('password', '')
        value = sanitize_and_validate(value, "password", 100)
        if value.lower() in WEAK_PASSWORDS:
            raise ValidationError("Senha muito fraca.")
        return value

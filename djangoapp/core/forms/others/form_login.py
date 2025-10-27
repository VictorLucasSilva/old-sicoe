from django import forms

class CustomLoginForm(forms.Form):
    login = forms.CharField(
        label='',
        widget=forms.TextInput(attrs={
            'placeholder': 'Usuário',
            'style': (
                'background-color: #f0f0f0; '
                'color: #000000; '
                'text-align: center; '
                'border-radius: 4px; '
                'padding: 5px; '
                'font-size: 16px; '
                'border: 1px solid #ddd; '
                'width: 100%;'
            )
        })
    )

    password = forms.CharField(
        label='',
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Senha',
            'style': (
                'background-color: #f0f0f0; '
                'color: #000000; '
                'text-align: center; '
                'border-radius: 4px; '
                'padding: 5px; '
                'font-size: 16px; '
                'border: 1px solid #ddd; '
                'width: 100%;'
            )
        })
    )

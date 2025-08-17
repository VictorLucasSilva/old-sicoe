from core.forms.administrador.form_update_adm import *

def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.fields['att_data_expire'].input_formats = ['%Y-%m-%d']
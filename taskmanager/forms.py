from django import forms
from taskmanager.models import Task


class NewTask(forms.ModelForm):
    url = forms.URLField(widget=forms.URLInput(attrs={'class': 'form-control'}))
    portscan = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}), required=False)
    nikto = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}), required=False)
    cms = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}), required=False)
    sql = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}), required=False)
    xss = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}), required=False)
    csrf = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}), help_text='Don\'t use Recursive on big dynamic sites! It will scan all the links on site<br>', required=False)
    recursive = forms.BooleanField(widget=forms.CheckboxInput(attrs={'class': 'checkbox'}),
                                   required=False)
    cookie = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control'}), required=False)

    class Meta:
        model = Task
        fields = ['url', 'portscan', 'nikto', 'cms', 'sql', 'xss', 'csrf',
                  'recursive', 'cookie']

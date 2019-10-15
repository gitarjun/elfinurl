from wtforms import Form, StringField, PasswordField, validators

class RegisterForm(Form):
    name = StringField('Name',[validators.length(min=1,max=50),validators.data_required()],render_kw={'readonly': False})
    username = StringField("Username",[validators.length(min=4,max=25),validators.data_required()],render_kw={'readonly': False})
    email = StringField("Email",[validators.Length(min=6,max=50),validators.data_required()],render_kw={'readonly': False})
    password = PasswordField("Password",
                             [validators.data_required(),
                              validators.EqualTo('confirm', message="Password Dont Match"),
                              validators.Length(min=6),
                              ])
    confirm = PasswordField("Confirm Password")

class ChangePassword(Form):
    current_password = PasswordField ('Current Password',
                                      [validators.data_required(),
                                       validators.Length(min=6),
                                       ])
    password = PasswordField("Password",
                             [validators.data_required(),
                              validators.EqualTo('confirm', message="Password Dont Match"),
                              validators.Length(min=6),
                              ])
    confirm = PasswordField("Confirm Password",
                            [validators.data_required(),
                              validators.Length(min=6),
                              ])

class LinkForm(Form):
    keyword = StringField('Key Word',[validators.length(min=1,max=200),validators.data_required()])
    link = StringField("Link",[validators.length(min=5),validators.data_required()])
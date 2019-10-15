**ElfinURL**
===================
ElfinURL is a url customization service written in python 3 with flask framework. With which user can change the landing page for given link.<br>
Live at "https://elfinurl.pythonanywhere.com/"


### Follwing things are implemented ###

* Registration with 2 factor authentication (Google Authenticator)
* SQLLite Database to store data
  * rootdb holds user credentials like
    * Name
    * Username
    * Password
    * 2factor authentication -secret
  * linkdb stores following
    * Link-keyword
    * Link
    * Visitors-count
    * Owner-id

* Change password
* User can opt for 2 factor authentication
* Generate QR Code for the custom link
* Holds max 10 links for the a user
* CSRF attack protection using CSRF token
* Added link visit counter

### Following things needs to be implemented ###

* Password reset email
* Delete account option to the user
* More advanced statistics for the visitors

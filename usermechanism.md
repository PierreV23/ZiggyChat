# Not Logged in:
`~/` -> buttons:
- Login -> `~/login`
- Register -> `~/register`
`~/settings` -> `~/`
`~/chat` -> `~/`

## `~/login`
UI with
- username
- password
- 2FA

## `~/register`
1. UI with
- username
- password
2. If [username is taken] {goto 3} else {goto 4}
3. Small red text saying username is taken, go back to step 1
4. Create a popup with a QR code and a text code of 2FA, prompting the user to fill in the 6 digits.


# Logged in:
- `~/` -> `~/chat`
- `~/login` -> `~/chat`
- `~/register` -> `~/chat`



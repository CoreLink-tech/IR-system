/**
 * A bounded list of very common passwords and the words people build passwords from (keyboard walks,
 * names, teams, places, seasons). It is NOT a breached-password database: it catches the passwords an
 * attacker tries first. To block more, point PASSWORD_BLOCKLIST_FILE at a text file with one entry per
 * line (see docs/SECURITY.md). Entries are compared after folding: lower case, letters and digits only,
 * and look-alike characters (0 o, 1 i, 3 e, 4 a, 5 s, 7 t, @ a, $ s, ! i) treated alike, so "P@ssw0rd"
 * and "password" are the same entry.
 */
export const COMMON_PASSWORDS: string[] = `
password passw0rd p4ssword pass word passwort passport password1 password12 password123 password1234
123456 1234567 12345678 123456789 1234567890 12345678910 111111 000000 121212 123123 654321 666666 112233
qwerty qwertyuiop qwerty123 qwertyui qwerasdf qweasd qweasdzxc qazwsx qazwsxedc qazxsw 1qaz2wsx 1q2w3e4r 1q2w3e4r5t
zaq12wsx zaq1xsw2 asdfgh asdfghjkl asdfasdf asdf1234 zxcvbn zxcvbnm zxcvbnm123 poiuytrewq mnbvcxz lkjhgfdsa
abc123 abcd1234 abcdef abcdefg abcdefgh abcdefghij aaaaaa aaaaaaaa abcabc iloveyou iloveyou1 iloveu ilovegod ilovemyself
letmein letmein1 welcome welcome1 welcome123 welcometo admin admin1 admin123 administrator adminadmin administrator1
root rootroot toor login login1 logmein master masterkey superuser supervisor sysadmin changeme changeit change123
secret secret1 secrets secure security securitypassword incident response incidentresponse monitoring dashboard
default guest guest123 test test1 test123 testing testtest tester demo sample example temp temp123 temporary
monkey dragon princess football baseball basketball soccer hockey tennis golf cricket rugby boxing wrestling
sunshine shadow superman batman spiderman ironman hulk captain avenger avengers starwars startrek pokemon naruto
trustno1 whatever freedom liberty america nigeria naija lagos abuja ibadan kano portharcourt enugu kaduna benin
jesus jesuschrist godisgood godbless godislove godfirst blessed blessing blessings emmanuel samuel daniel david
michael jennifer jordan hunter ranger buster thomas tigger robert george andrew harley ginger joshua matthew
nicole jessica ashley amanda hannah tiffany charlie donald mustang access flower hottie summer winter spring autumn
january february march april may june july august september october november december monday tuesday friday sunday
chelsea arsenal liverpool manutd manchester barcelona realmadrid juventus ronaldo messi neymar lebron jordan23
hello hello123 helloworld hellothere hithere howdy computer internet laptop desktop windows linux ubuntu google
facebook twitter instagram whatsapp telegram youtube netflix amazon apple microsoft samsung iphone android
love lover loveme lovely loveyou love123 lovelove baby babygirl angel angels heaven forever friends family
money rich richard cash gold diamond silver purple orange yellow green blue black white pink red
dolphin tiger eagle falcon phoenix wolf lion panther cobra viper shark hawk raven
bailey maggie sophie lucky cookie pepper buddy rocky max coco molly oliver ginger
mother father brother sister daughter son wife husband
shop shopping store market ecommerce website webmaster server database mysql nginx apache php
company business office work worker employee manager director staff
1qaz2wsx3edc 1qaz2wsx3edc4rfv 1qaz2wsx3edc4rfv5tgb qazwsxedcrfv qazwsxedcrfvtgb 1q2w3e4r5t6y 1q2w3e4r5t6y7u8i 1q2w3e4r5t6y7u8i9o0p qwertyuiopasdfghjkl asdfghjklzxcvbnm zxcvbnm1 1qazxsw2 q1w2e3r4 q1w2e3r4t5 qazwsx123 1qaz1qaz 123qwe 123qweasd 123abc 1234abcd a1b2c3d4 a1b2c3
11111111 22222222 00000000 12341234 11223344 123454321 987654321 9876543210 147258369 159753 1357924680
pass1234 pass123 passpass password! passw0rd1 p@ssw0rd p@ssword pa55word pa55w0rd
trustno letmein123 iloveyou123 sunshine1 princess1 football1 baseball1 monkey123 dragon123 master123
`.split(/\s+/).filter(Boolean);

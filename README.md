# Fetures
## Require:

[x] The user can create an account with password and unique username, email. If the username and email already exists, the user has to use another username/email.

[x] Once the user successfully create his account, he can use that account to log in (authentication required).

[x] The user can see all posts on homepage, includes these info:

title,
body (with body limit to 50-100 characters),
date created,
date updated,
author
(optional: with odd and even posts in different color for better readability)
The user can see full details of each post by clicking on the post’s title.

[x] The user should be able to comment on each post

[x] The user will see comments which belongs to that specific post.
(if you have done the voting in optional, do this: the user should be able to see votes attached to each comment.)

[x] The user should be able to edit his own posts.

[x] The user should not be able to see (and use) edit and delete buttons for a post that does not belong to him (note: what if he has access to your edit/delete url?)

[x] The user should be able to edit his own comments.

[x] The user should not be able to edit/delete comments that do not belong to him

##Optional:
[x] The user can see posts that belong to a specific author only when clicking on that author name.
The user should be able to see a “top bloggers” page (by clicking on a link on navbar), which have statistics on top posters, top commenters, top populars (most up vote)
Follow feature

[] The user can follow other users by clicking on the button (e.g “follow username”), clicking again on “unfollow* username” will unfollow him.
(*when user already follow a user, the text will change from follow to unfollow)
The user can see posts that belong to those he is following by accessing the “following” tab (on navbar)
The user can also see who he is following and who’s following him by accessing the 2 pages following list, follower list on the navbar, inside the dropdown on the user’s username
Voting feature

[x] The user should also upvote (or downvote) on each post and comment. User should not be able to upvote or downvote more than 1 point, attempting to vote (up or down) more than once will result the vote that specific user voted goes back to 0
(Take a look at Stack overflow as an example. You can change the voting system to your liking, e.g when user already vote up/down, they cannot vote up/down again unless they vote down/up )
The user can also see the number of comments, votes for each post on the home page.
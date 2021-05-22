# Decision making in the curl project

A rough guide to how we make decisions and who does what.

## BDFL

This project was started by and has to some extent been pushed forward over
the years with Daniel Stenberg as the driving force. It matches a standard
BDFL (Benevolent Dictator For Life) style project.

This setup has been used due to convenience and the fact that is has worked
fine this far. It is not because someone thinks of it as a superior project
leadership model. It will also only continue working as long as Daniel manages
to listen in to what the project and the general user population wants and
expects from us.

## Legal entity

There is no legal entity. The curl project is just a bunch of people scattered
around the globe with the common goal to produce source code that creates
great products. We are not part of any umbrella organization and we are not
located in any specific country. We are totally independent.

The copyrights in the project are owned by the individuals and organizations
that wrote those parts of the code.

## Decisions

The curl project is not a democracy, but everyone is entitled to state their
opinion and may argue for their sake within the community.

All and any changes that have been done or will be done are eligible to bring
up for discussion, to object to or to praise. Ideally, we find consensus for
the appropriate way forward in any given situation or challenge.

If there is no obvious consensus, a maintainer who's knowledgeable in the
specific area will take an "executive" decision that they think is the right
for the project.

## Donations

Donating plain money to curl is best done to curl's [Open Collective
fund](https://opencollective.com/curl). Open Collective is a US based
non-profit organization that holds on to funds for us. This fund is then used
for paying the curl security bug bounties, to reimburse project related
expenses etc.

Donations to the project can also come in form of server hosting, providing
services and paying for people to work on curl related code etc. Usually, such
donations are services paid for directly by the sponsors.

We grade sponsors in a few different levels and if they meet the criteria,
they can be mentioned on the Sponsors page on the curl website.

## Commercial Support

The curl project does not do or offer commercial support. It only hosts
mailing lists, runs bug trackers etc to facilitate communication and work.

However, Daniel works for wolfSSL and we offer commercial curl support there.

## Key roles

### Maintainers

A maintainer in the curl project is an individual who has been given
permissions to push commits to one of the git repositories.

Maintainers are free to push commits to the repositories at their own will.
Maintainers are however expected to listen to feedback from users and any
change that is non-trivial in size or nature *should* be brought to the
project as a PR to allow others to comment/object before merge.

### Former maintainers

A maintainer who stops being active in the project will at some point get
their push permissions removed. We do this for security reasons but also to
make sure that we always have the list of maintainers as "the team that push
stuff to curl".

Getting push permissions removed is not a punishment. Everyone who ever worked
on maintaining curl is considered a hero, for all time hereafter.

### Security team members

We have a security team. That's the team of people who are subscribed to the
curl-security mailing list; the receivers of security reports from users and
developers. This list of people will vary over time but should be skilled
developers familiar with the curl project.

The security team works best when it consists of a small set of active
persons. We invite new members when the team seems to need it, and we also
expect to retire security team members as they "drift off" from the project or
just find themselves unable to perform their duties there.

### Server admins

We run a web server, a mailing list and more on the curl project's primary
server. That physical machine is owned and run by Haxx. Daniel is the primary
admin of all things curl related server stuff, but Björn Stenberg and Linus
Feltzing serve as backup admins for when Daniel is gone or unable.

The primary server is paid for by Haxx. The machine is physically located in a
server bunker in Stockholm Sweden, operated by the company Portlane.

The website contents are served to the web via Fastly and Daniel is the
primary curl contact with Fastly.

### BDFL

That's Daniel.

# Maintainers

A curl maintainer is a project volunteer who has the authority and rights to
merge changes into a git repository in the curl project.

Anyone can aspire to become a curl maintainer.

### Duties

There are no mandatory duties. We hope and wish that maintainers consider
reviewing patches and help merging them, especially when the changes are
within the area of personal expertise and experience.

### Requirements

- only merge code that meets our quality and style guide requirements.
- *never* merge code without doing a PR first, unless the change is "trivial"
- if in doubt, ask for input/feedback from others

### Recommendations

- we require two-factor authentication enabled on your GitHub account to
  reduce risk of malicious source code tampering
- consider enabling signed git commits for additional verification of changes

### Merge advice

When you're merging patches/PRs...

- make sure the commit messages follow our template
- squash patch sets into a few logical commits even if the PR didn't, if
  necessary
- avoid the "merge" button on GitHub, do it "manually" instead to get full
  control and full audit trail (github leaves out you as "Committer:")
- remember to credit the reporter and the helpers!

## Who are maintainers?

The [list of maintainers](https://github.com/orgs/curl/people). Be aware that
the level of presence and activity in the project vary greatly between
different individuals and over time.

### Become a maintainer?

If you think you can help making the project better by shouldering some
maintaining responsibilities, then please get in touch.

You will be expected to be familiar with the curl project and its ways of
working. You need to have gotten a few quality patches merged as a proof of
this.

### Stop being a maintainer

If you (appear to) not be active in the project anymore, you may be removed as
a maintainer. Thank you for your service!

package Net::SCP;

use strict;
use vars qw($VERSION @ISA @EXPORT_OK $scp);
use Exporter;
use Carp;
use File::Basename;
use String::ShellQuote;
use IO::Handle;
use Net::SSH qw(sshopen3);
use IPC::Open3;

@ISA = qw(Exporter);
@EXPORT_OK = qw( scp iscp );
$VERSION = '0.04';

$scp = "scp";

=head1 NAME

Net::SCP - Perl extension for secure copy protocol

=head1 SYNOPSIS

  #procedural interface
  use Net::SCP qw(scp iscp);
  scp($source, $destination);
  iscp($source, $destination); #shows command, asks for confirmation, and
                               #allows user to type a password on tty

  #OO interface
  $scp = Net::SCP->new( "hostname", "username" );
  #with named params
  $scp = Net::SCP->new( { "host"=>$hostname, "user"=>$username } );
  $scp->get("filename") or die $scp->{errstr};
  $scp->put("filename") or die $scp->{errstr};
  #tmtowtdi
  $scp = new Net::SCP;
  $scp->scp($source, $destination);

  #Net::FTP-style
  $scp = Net::SCP->new("hostname");
  $scp->login("user");
  $scp->cwd("/dir");
  $scp->size("file");
  $scp->get("file");
  $scp->quit;

=head1 DESCRIPTION

Simple wrappers around ssh and scp commands.

=head1 SUBROUTINES

=over 4

=item scp SOURCE, DESTINATION

Can be called either as a subroutine or a method; however, the subroutine
interface is depriciated.

Calls scp in batch mode, with the B<-B> B<-p> B<-q> and B<-r> options.
Returns false upon error, with a text error message accessable in
$scp->{errstr}.

Returns false and sets the B<errstr> attribute if there is an error.

=cut

sub scp {
  my $self = ref($_[0]) ? shift : {};
  my($src, $dest, $interact) = @_;
  my $flags = '-p';
  $flags .= 'r' unless &_islocal($src) && ! -d $src;
  my @cmd;
  if ( ( defined($interact) && $interact )
       || ( defined($self->{interact}) && $self->{interact} ) ) {
    @cmd = ( $scp, $flags, $src, $dest );
    print join(' ', @cmd), "\n";
    unless ( &_yesno ) {
      $self->{errstr} = "User declined";
      return 0;
    }
  } else {
    $flags .= 'qB';
    @cmd = ( $scp, $flags, $src, $dest );
  }
  my($reader, $writer, $error ) =
    ( new IO::Handle, new IO::Handle, new IO::Handle );
  $writer->autoflush(1);#  $error->autoflush(1);
  my $pid = open3($writer, $reader, $error, @cmd );
  waitpid $pid, 0;
  if ( $? >> 8 ) {
    my $errstr = join('', <$error>);
    #chomp(my $errstr = <$error>);
    $self->{errstr} = $errstr;
    0;
  } else {
    1;
  }
}

=item iscp SOURCE, DESTINATION

Can be called either as a subroutine or a method; however, the subroutine
interface is depriciated.

Prints the scp command to be execute, waits for the user to confirm, and
(optionally) executes scp, with the B<-p> and B<-r> flags.

Returns false and sets the B<errstr> attribute if there is an error.

=cut

sub iscp {
  if ( ref($_[0]) ) {
    my $self = shift;
    $self->{'interact'} = 1;
    $self->scp(@_);
  } else {
    scp(@_, 1);
  }
}

sub _yesno {
  print "Proceed [y/N]:";
  my $x = scalar(<STDIN>);
  $x =~ /^y/i;
}

sub _islocal {
  shift !~ /^[^:]+:/
}

=back

=head1 METHODS

=over 4

=item new HOSTNAME [ USER ] | HASHREF

This is the constructor for a new Net::SCP object.  You must specify a
hostname, and may optionally provide a user.  Alternatively, you may pass a
hashref of named params, with the following keys:

    host - hostname
    user - username
    interactive - bool
    cwd - current working directory on remote server

=cut

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self;
  if ( ref($_[0]) ) {
    $self = shift;
  } else {
    $self = {
              'host'        => shift,
              'user'        => ( scalar(@_) ? shift : '' ),
              'interactive' => 0,
              'cwd'         => '',
            };
  }
  bless($self, $class);
}

=item login [USER]

Compatibility method.  Optionally sets the user.

=cut

sub login {
  my($self, $user) = @_;
  $self->{'user'} = $user if $user;
}

=item cwd CWD

Sets the cwd (used for a subsequent get or put request without a full pathname).

=cut

sub cwd {
  my($self, $cwd) = @_;
  $self->{'cwd'} = $cwd || '/';
}

=item get REMOTE_FILE [, LOCAL_FILE]

Uses scp to transfer REMOTE_FILE from the remote host.  If a local filename is
omitted, uses the basename of the remote file.

=cut

sub get {
  my($self, $remote, $local) = @_;
  $remote = $self->{'cwd'}. "/$remote" if $self->{'cwd'} && $remote !~ /^\//;
  $local ||= basename($remote);
  my $source = $self->{'host'}. ":$remote";
  $source = $self->{'user'}. '@'. $source if $self->{'user'};
  scp($source,$local);
}

=item size FILE

Returns the size in bytes for the given file as stored on the remote server.
Returns 0 on error, and sets the B<errstr> attribute.  In the case of an actual
zero-length file on the remote server, the special value '0e0' is returned,
which evaluates to zero when used as a number, but is true.

(Implementation note: An ssh connection is established to the remote machine
and wc is used to determine the file size.)

=cut

sub size {
  my($self, $file) = @_;
  $file = $self->{'cwd'}. "/$file" if $self->{'cwd'} && $file !~ /^\//;
  my $host = $self->{'host'};
  $host = $self->{'user'}. '@'. $host if $self->{'user'};
  my($reader, $writer, $error ) =
    ( new IO::Handle, new IO::Handle, new IO::Handle );
  $writer->autoflush(1);#  $error->autoflush(1);
  #sshopen2($host, $reader, $writer, 'wc', '-c ', shell_quote($file) );
  my $pid =
    sshopen3($host, $writer, $reader, $error, 'wc', '-c ', shell_quote($file) );
  waitpid $pid, 0;
  if ( $? >> 8 ) {
    chomp(my $errstr = <$error>);
    $self->{errstr} = $errstr || "wc exited with status ". $?>>8;
    0;
  } else {
    chomp( my $size = <$reader> || 0 );
    if ( $size =~ /^\s*(\d+)/ ) {
      $1 ? $1 : '0e0';
    } else {
      $self->{errstr} = "unparsable output from remote wc: $size";
      0;
    }
  }
}

=item put LOCAL_FILE [, REMOTE_FILE]

Uses scp to trasnfer LOCAL_FILE to the remote host.  If a remote filename is
omitted, uses the basename of the local file.

=cut

sub put {
  my($self, $local, $remote) = @_;
  $remote ||= basename($local);
  $remote = $self->{'cwd'}. "/$remote" if $self->{'cwd'} && $remote !~ /^\//;
  my $dest = $self->{'host'}. ":$remote";
  $dest = $self->{'user'}. '@'. $dest if $self->{'user'};
  warn "scp $local $dest\n";
  scp($local, $dest);
}

=item binary

Compatibility method: does nothing; returns true.

=cut

sub binary { 1; }

=back

=head1 AUTHORS

Ivan Kohler <ivan-netscp_pod@420.am>
Anthony Deaver <bishop@projectmagnus.org>

Thanks to Jon Gunnip <jon@soundbite.com> for fixing a bug with size().

=head1 BUGS

Still has no-OO cruft.

In order to work around some problems with commercial SSH2, if the source file
is on the local system, and is not a directory, the B<-r> flag is omitted.

It's probably better just to use SSH1 or OpenSSH <http://www.openssh.com/>

The Net::FTP-style OO stuff is kinda lame.  And incomplete.

=head1 SEE ALSO

scp(1), ssh(1)

=cut

1;



package Net::SCP;

use strict;
use vars qw($VERSION @ISA @EXPORT_OK $scp);
use Exporter;
use File::Basename;
use String::ShellQuote;
use IO::Handle;
use Net::SSH qw(sshopen3);

@ISA = qw(Exporter);
@EXPORT_OK = qw( scp iscp );
$VERSION = '0.01';

$scp = "scp";

=head1 NAME

Net::SCP - Perl extension for secure copy protocol

=head1 SYNOPSIS

  #procedural interface
  use Net::SCP qw(scp iscp);
  scp($source, $destination);
  iscp($source, $destination); #shows command, asks for confirmation, and
                               #allows user to type a password on tty

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

Calls scp in batch mode, with the B<-B> B<-p> B<-q> and B<-r> options.

=cut

sub scp {
  my($src, $dest) = @_;
  my $flags = '-Bpq';
  $flags .= 'r' unless &_islocal($src) && ! -d $src;
  my @cmd = ( $scp, $flags, $src, $dest );
  system(@cmd);
}

=item iscp SOURCE, DESTINATION

Prints the scp command to be execute, waits for the user to confirm, and
(optionally) executes scp, with the B<-p> and B<-r> flags.

=cut

sub iscp {
  my($src, $dest) = @_;
  my $flags = '-p';
  $flags .= 'r' unless &_islocal($src) && ! -d $src;
  my @cmd = ( $scp, $flags, $src, $dest );
  print join(' ', @cmd), "\n";
  if ( &_yesno ) {
    system(@cmd);
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

=item new HOSTNAME

This is the constructor for a new Net::SCP object.  Additional parameters
are ignored.

=cut

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self = {
               'host' => shift,
               'user' => '',
               'cwd'  => '',
             };
  bless($self, $class);
}

=item login [USER]

Compatibility method.  Optionally sets the user.

=cut

sub login {
  my($self, $user) = @_;
  $self->{'user'} = $user;
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

(Implementation note: An ssh connection is established to the remote machine
and wc is used to determine the file size.  No distinction is currently made
between nonexistant and zero-length files.)

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
  sshopen3($host, $writer, $reader, $error, 'wc', '-c ', shell_quote($file) );
  chomp( my $size = <$reader> || 0 );
  if ( $size =~ /^\s+(\d+)/ ) {
    $1;
  } else {
    warn "unparsable output from remote wc";
    0;
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

=head1 AUTHOR

Ivan Kohler <ivan-netscp@420.am>

=head1 BUGS

Not OO.

In order to work around some problems with commercial SSH2, if the source file
is on the local system, and is not a directory, the B<-r> flag is omitted.

It's probably better just to use SSH1 or OpenSSH <http://www.openssh.com/>

The Net::FTP-style OO stuff is kinda lame.  And incomplete.

=head1 SEE ALSO

scp(1), ssh(1)

=cut

1;



require "socket"

@[Link("krb5")]
lib LibKRB
  type Context = Void*
  type CCache = Void*
  type INcreds = Void*
  type Outcreds = Void*
  fun init_context = krb5_init_context(context : Context*) : LibC::UInt
  fun free_context = krb5_free_context(context : Context*)
  fun get_credentials = krb5_get_credentials(context : Context*,
                                             options : Int32,
                                             ccache : CCache*,
                                             in_creds : INcreds*,
                                             out_creds : Outcreds*)
  fun default_cache = krb5_cc_default(context : Context*, ccache : CCache*) : LibC::UInt
  fun to_error = krb5_get_error_message(context : Context*, error_code : LibC::UInt) : LibC::Char*
end

class KerberosException
  def initialize(status)
    raise "Kerberos Error: #{Krb5.get_error(status)}"
  end
end

class Krb5
  def initialize
    @ctx = uninitialized LibKRB::Context
    @ccache = uninitialized LibKRB::CCache
  end

  def get_error(status)
    status = LibKRB.to_error(pointerof(@ctx), status)
    String.new(status)
  end

  def get_info
    puts "CTX: #{@ctx}"
    puts "CCache: #{@ccache}"
  end

  def free
    LibKRB.free_context(pointerof(@ctx))
  end

  def init_context
    status = LibKRB.init_context(out @ctx)
    raise "krb5_init_context() failed: #{get_error(status)}" unless status == 0
  end

  def init_ccache
    status = LibKRB.default_cache(pointerof(@ctx), pointerof(@ccache))
    raise "Cannot initiate CCache: #{get_error(status)}" unless status == 0
  end

  def get_creds(user)
    LibKRB.get_credentials
  end
end

krb5 = Krb5.new
krb5.get_info
krb5.init_context
krb5.get_info
krb5.init_ccache
krb5.get_info
# krb5.free

#!/usr/bin/env ruby

require 'logger'
require 'fileutils'
require 'tempfile'
require 'optparse'
require 'thread'


# Class that holds the required metadata of a peer such as
# hostname, Pastry port rmi port and ID
# Author:: Asterios KATSIFODIMOS
# Creation Date:: 01/03/2010
# Last Modification Date:: 16/05/2011
class Peer
  attr_accessor :hostname, :port, :rmi_port, :id
  # Class contructor of the Peer class
  def initialize(hostname, port, rmi_port, id)
    @hostname = hostname
    @port     = port
    @rmi_port = rmi_port
    @id       = id
  end

  #Converts the peer to the usual hostname:port,port ID representation string
  def to_str()
    return "#{hostname}:#{port},#{rmi_port}"
  end

  #Converts the peer to the usual hostname:port,port ID representation string
  def to_s()
    return to_str()
  end
end

# This class is the main deployer class that is used to deploy ViP2P. The 
# deployer is using the standard ruby logger to log things both the the log 
# file (default is deployer.log) and to the console. It provides the neccessary 
# functions to start/stop a ViP2P network as well as execute remote commands to 
# physical machines or force the  killing of stalled peers.
# 
# Author:: Asterios KATSIFODIMOS
# Creation Date:: 01/03/2010
# Last Modification Date:: 16/05/2011
class Deployer
  
  attr_accessor :config, :peers, :logger

  #Constructor of the Deployer class
  def initialize()
    @deployer_log           = "deployment.log"
    @logger               ||= Logger.new(@deployer_log)
    @logger.level           = Logger::INFO
    @logger.datetime_format = " %Y-%m-%d %H:%M:%S "
    
    load_defaults()

    parse_options()

    @config = parse_config(@config_file)

    check_environment()

    @peers = Array.new
    @physical_hosts = Hash.new
    @remote_root = config['deployTo']+"/vip2pScript/"
    @ssh_port = config['sshPort'] ? config['sshPort'] : "22"

    generate_peers()
  end

  # Loads the default values for all the important variables
  def load_defaults()
    #Constants and default values
    @DOCS_FOLDER           = "docs"
    @VIEWS_FOLDER          = "views"
    @QUERIES_FOLDER        = "queries"
    @UPDATES_FOLDER        = "updates"
    @SCENARIO_FOLDER       = "scenario"
    @SCHEMAS_FOLDER        = "schemas"
    @STORAGE_BUDGET_FOLDER = "storage_budget"
    
    @files_to_sync             =  ["Log4jConfig.xml", "ViP2P.conf"]
    @files_to_sync_for_source  =  ["src", "libs", "Makefile"]
    
    @config_file  = "deployment.conf"
    @hosts_file   = "hosts"
    @jar_file     = "ViP2P.jar"
    @vip2p_config = "ViP2P.conf"
    @log_repo     = "logs/"

    @remote_execution_mode    = false
    @remote_execution_command = String.new
    @jar_mode       = false
    @get_logs_mode  = false
    @stop_mode = false
    @kill_mode = false
    
  end

  # Parses the command line options - also serves as a usage message building function
  def parse_options()

    options = OptionParser.new do |opts|
      opts.banner = "Usage: deployer.rb [action] [options]"

      opts.separator ""
      opts.separator "Available actions:"

      opts.on("-s", "--stop", "Shuts down the ViP2P peer network. Combine with --jar to stop using the jar file.") do
        @stop_mode = true
      end

      opts.on("-l", "--get-logs [DIRECTORY]", "Retrieve all the logs and statistics for all peers and store them in DIRECTORY. " +
      "Default: ./logs.") do |arg|
        @get_logs_mode  = true
        @log_repo       = arg || "logs"
      end

      opts.on("-e", "--execute \"COMMAND\"", "Runs the specified COMMAND in all physical machines.") do |arg|
        @remote_execution_mode    = true
        @remote_execution_command = arg
      end

      opts.on("-k", "--kill", "Forces the killing (kill -9) of all peers in the network. "+
      "Use only when things go wrong.") do
        @kill_mode = true
      end

      opts.separator ""
      opts.separator "Available options (optional):"

      opts.on("-c", "--config FILE",  "The FILE that contains the deployment parameters. "+
      "Default: ./deployment.conf") do |arg|
        @config_file = arg
      end

      opts.on("-h", "--hosts FILE", "The FILE that contains the hosts that will "+
      "be used for the deployment. Default: ./hosts.") do |arg|
        @hosts_file = arg || "hosts"
      end

      opts.on("-j", "--jar [FILE]", "Start/Stop the network using the jar FILE (instead of the code). Default: ./ViP2P.jar.") do |arg|
        @jar_file = arg || "ViP2P.jar"
        @files_to_sync << @jar_file
        @jar_mode = true
      end

      opts.separator ""
      opts.separator "Other options:"

      opts.on("-d", "--debug", "Run deployer in debug mode") do
        logger.level = Logger::DEBUG
      end

      opts.on_tail("--help", "Show this help message") do
        puts opts
        exit
      end
    end

    options.parse!

  end

  # Parses the config file given as a parameter and returns a hash of 
  # configuration variables and their values
  def parse_config(config)
    file = File.open(config, "r")
    a_hash = {}
    file.each_line do |line|

      if (line.lstrip).index('#') == 0
        next
      end

      if line.include?("=")
        key, value = line.split("=")
        a_hash = a_hash.merge({"#{key.lstrip.rstrip}" => "#{value.lstrip.rstrip}"})
      end
    end

    file.close

    return a_hash
  end

  # Function that checks the environment making sure that all needed files are 
  # in place and (according to the current mode: start/stop/get-logs/execute), 
  # that variables contain the sane values.
  def check_environment()

    if ! File.exist?(@hosts_file)
      logger.fatal("The hosts file: '#{@hosts_file}' does not exist.")
      exit(1)
    end

    if @jar_mode and ! File.exist?(@jar_file)
      logger.fatal("The Jar file: '#{@jar_file}' does not exist.")
      exit(1)
    end

    if ! File.exist?(@vip2p_config)
      logger.fatal("The ViP2P config file: '#{@vip2p_config}' does not exist.")
      exit(1)
    end

    if ! File.exist?(config['pathToDataset'])
      logger.fatal("The pathToDataset: '#{@config['pathToDataset']}' does not exist.")
      exit(1)
    end

    if ! File.exist?(config['SSHConnectKey'])
      logger.fatal("The SSHConnectKey: '#{@config['SSHConnectKey']}' does not exist.")
      exit(1)
    end

    if not @jar_mode

      #In stop mode, we need the class directory that we will use to call the controlmodule
      if  @stop_mode
        #Either we are on a development machine that bin contains the class files or we are
        #somewhere else where the build directory contains the class files
        if File.exist?("bin")
          @class_dir = "bin/"
        elsif File.exist?("build")
          @class_dir = "build/"
        else
          logger.fatal("Could not locate either the bin or the build directory. Either compile the code or use the --jar option.")
          exit(1)
        end
      end

      #If we are not in a stop mode, we have to have the src directory that contains the sources that
      #we are going to move to the deployment machines
      if not @stop_mode and not File.exist?("src")
        logger.fatal("Could not locate the src directory.")
        exit(1)
      end

      #If we are going to use the src, we also need the libraries
      if not @stop_mode and not File.exist?("libs")
        logger.fatal("Could not locate the libs directory.")
        exit(1)
      end

      @files_to_sync << @files_to_sync_for_source

    end

    #If we are running on jar mode only the jar file has to be included in the classpath, else, all the .jar files under libs
    @classpath = @jar_mode ? @jar_file : `find ./libs | grep ".jar$"`.gsub("\n",":")+":#{@class_dir}:./build/"

  end
  
  # Displays an overview of the deployment: queries/documents/views/schemata
  # etc that each peer involved in the deployment will be assigned.
  def display_overview
    logger << "\n\n\tDeployment Overview:"
    logger << "\t------------------------------------------------------------------------------------------"
    peers.each do |peer|
      docs     = Dir[config['pathToDataset'] + "/" + @DOCS_FOLDER      + "/" + peer.id.to_s + "/"+"*.xml"].size
      queries  = Dir[config['pathToDataset'] + "/" + @QUERIES_FOLDER   + "/" + peer.id.to_s + "/"+"*.xam"].size
      views    = Dir[config['pathToDataset'] + "/" + @VIEWS_FOLDER     + "/" + peer.id.to_s + "/"+"*.xam"].size
      scenario = Dir[config['pathToDataset'] + "/" + @SCENARIO_FOLDER  + "/" + peer.id.to_s + "/"+"*.txt"].size!=0
      schemas  = Dir[config['pathToDataset'] + "/" + @SCHEMAS_FOLDER   + "/" + peer.id.to_s + "/"+"*.sch"].size
      logger << "\t| Peer: %-5s | %4s docs | %4s views | %4s queries | %4s schemas |    %s\n" % [peer.id.to_s, docs, views, queries, schemas, scenario ? "by scenario    |" : "random mode    |"]
    end
    logger << "\t------------------------------------------------------------------------------------------"
    logger << "\n\n"
  end

  # Returns an ssh command string formated with the the options taken from the 
  # deployment file and the hostname argument.
  def ssh(hostname) 
    return "ssh -p #{@ssh_port} -o StrictHostKeyChecking=no -x -n  -i #{config['SSHConnectKey']} -l #{config['userName']} #{hostname} "
  end

  # Return an rsync command string formated with the the options taken from the
  # deployment file.
  def rsync()
    return "rsync -r -v -z -e \"ssh -p #{@ssh_port}  -o StrictHostKeyChecking=no -x -i #{config['SSHConnectKey']} -l #{config['userName']}\" --delete --exclude=\".svn/\" "
  end

  # Executes a given system command. if check_exit_status=true then any function
  # that exits with return code !=0 will cause the deployer to stop and report 
  # the problem. This is useful in cases where we need to be sure that the 
  # commands we are executing finish normally (e.g. rsync, scp etc).
  def execute(command, verbose=false, check_exit_status=true)
    logger.debug("[Execute Command] Executing: " + command)

    status = Open4.popen4(command) {|pid, stdin, stdout, stderr|
      out = Thread.new do
        stdout.each_line do |line|
          if verbose
            logger << line
          end
        end
      end

      err = Thread.new do
        stderr.each_line do |line|
          logger << line
        end
      end

      out.join
      err.join
    }

    @logger.debug("[Execute Command]" + command + " exit status: " + status.to_s)

    #If something goes wrong, we are going to report the problem and exit
    if check_exit_status and Integer(status.to_s)!=0
      @logger.fatal("[Execute Command]" + command + " exit status: " + status.to_s)
      @logger.close()
      exit 1
    end
  end

  # Function that creates the peers given the deployment configuration and the 
  # list of physical hosts. The peers are sored in an array and used all over 
  # the class.
  def generate_peers()
    starting_port = Integer(config['portRangeStart'])+1
    peer_id = 1
    File.open(@hosts_file).each_line do |host|
      #Skip commented and empty lines
      next if !host || host.gsub!("\n","")==""|| host.index("#")==0

      @physical_hosts[host] = []
      Integer(config['peersPerPhyMachine']).times do |count|
        peers << Peer.new(host, starting_port, starting_port+1, peer_id)
        @physical_hosts[host] << peers.last
        logger.debug("Created peer: " + peers.last)
        starting_port+=2
        peer_id+=1
      end
    end
  end

  # Function that is used to distribute the data to the physical machines
  # and accordingly to the peers that are to run in each physical machine.
  # First it moves the code or ViP2P.jar + the configuration files to the
  # physical machines. The it uses the function send_peer_data to send the
  # data (docs, queries, etc) to the folders of each peer.
  def distribute_data()
    mutex = Mutex.new
    percentage=0
    logger.info("[Distributing Data...]")
    percentage = 0.0
    threads = ThreadPool.new(100)

    peers.each do |peer|
      threads.execute {
        logger.info("[ #{Integer(100*(percentage/peers.size))}% ][Distributing Peer Data] Peer ##{peer.id}: Started")

        send_peer_data(peer)
        execute(ssh(peer.hostname) + "\'rm -rf #{@remote_root}/logs/ #{@remote_root}/plans/; mkdir -p #{@remote_root}/logs/ ;mkdir -p #{@remote_root}/plans/ \'")

        mutex.synchronize {percentage += 1}
        logger.info("[ #{Integer(100*(percentage/peers.size))}% ][Distributing Peer Data] Peer ##{peer.id}: Finished")
      }
    end

    threads.join()
    percentage = 0.0

    @physical_hosts.each do |hostname, peers|
      threads.execute {
        logger.info("[ #{Integer(100*(percentage/@physical_hosts.size))}% ][Distributing code & config files] Physical Machine #{hostname}: Started")
        execute(rsync + " #{@files_to_sync.entries.join(" ")} #{hostname}:#{@remote_root}/")
        mutex.synchronize {percentage += 1}
        logger.info("[ #{Integer(100*(percentage/@physical_hosts.size))}% ][Distributing code & config files] Physical Machine #{hostname}: Finished")
      }
    end

    threads.join()
    threads.close()
  end

  # Function that given a peer, decides which data is going to send to the 
  # physical machine running it and send them. It starts by examining which 
  # folders (docs, queries, scenario, views, updates) are needed to be 
  # trasnfered and then transfers them all in bulk. peer is the peer object to 
  # whom the data will be sent.
  def send_peer_data(peer)
    threads = ThreadPool.new(8)
    remote_peer_directory = @remote_root + "#{peer.hostname}:#{peer.port},#{peer.rmi_port}/"

    logger.debug("Remote peer directory: " + remote_peer_directory)

    to_be_moved = []
    to_be_deleted = []

    folders = [@DOCS_FOLDER, @QUERIES_FOLDER, @VIEWS_FOLDER, @UPDATES_FOLDER, @SCHEMAS_FOLDER]

    # for each folder type, check whether the folder contains any files. If yes, add it to the list of
    # to_be_moved else add it to the list of fodlers that are going to be deleted from the remote directory
    # (to_be_deleted)
    folders.each do |folder|

      local_data_directory  = config['pathToDataset'] + "/" + folder + "/" + peer.id.to_s + "/"

      #if the directory does not exist or it contains no files at all, it will be marked for deletion
      if (!File.exist?(local_data_directory)) || (Dir[local_data_directory+"*"].size == 0)
        logger.debug("Local data drectory " + local_data_directory + " does not exist. Will have to remove the remote one (#{remote_peer_directory + folder}).")
        to_be_deleted << remote_peer_directory + folder
        # else, it is going to be added to the list of folders that have to be synchronized
      else
        logger.debug("Folder #{local_data_directory} contains some files, we are going to move stuff from it.")
        logger.debug("#{folder} is going to be copied to the remote directory.")
        to_be_moved << folder
      end
    end

    peer_scenario_folder = config['pathToDataset'] + "/" + @SCENARIO_FOLDER + "/" + peer.id.to_s + "/"
    has_scenario = File.exists?(peer_scenario_folder+"scenario.txt")
    to_be_deleted << remote_peer_directory + "berkeley"

    if !has_scenario
      to_be_deleted << remote_peer_directory + "scenario.txt"
    end

    # Prepare the remove command that will remove all folders that are not needed any more in tha remote peer directory
    rm_command = to_be_deleted.empty? ? "" : "rm -rf #{to_be_deleted.entries.join(' ')}"

    #If a scenario is involved, we have to put everything under /.tmp/
    destination_folder = has_scenario ? "/.tmp/" : "/"

    #Prepare the environment that the fiels will be hosted into (directories etc) and make sure that no file exists on the
    #remote side that is not supposed to be there (e.g. a scenario file was there but now it is removed from the local dataset dir)
    execute("#{ssh(peer.hostname)} \" #{rm_command} ;mkdir -p #{remote_peer_directory}/#{destination_folder}; cd #{remote_peer_directory}/#{destination_folder}; mkdir -p #{folders.entries.join(' ')}; #{ has_scenario ? "cd ../;rm -rf + #{folders.entries.join(' ')}" : ""} \"")

    if has_scenario
      threads.execute{
        execute(rsync() + " #{config['pathToDataset']}/#{@SCENARIO_FOLDER}/#{peer.id.to_s}/scenario.txt" + " #{peer.hostname}:\'#{remote_peer_directory}/\'")
      }
    end

    # Synchronize all the folders that were found to contain at least one file
    to_be_moved.each  do |folder|
      threads.execute{
        execute(rsync() + " #{config['pathToDataset']}/#{folder}/#{peer.id.to_s}/" + " #{peer.hostname}:\'#{remote_peer_directory}/#{destination_folder}/#{folder}/\'")
      }
    end

    # Move the storage budget to the remote peer directory
    threads.execute{
	  if File.exists?("#{config['pathToDataset']}/#{@STORAGE_BUDGET_FOLDER}/#{peer.id.to_s}/storage_budget.conf")
      	execute(rsync() + " #{config['pathToDataset']}/#{@STORAGE_BUDGET_FOLDER}/#{peer.id.to_s}/storage_budget.conf #{peer.hostname}:\'#{remote_peer_directory}/\'")
      end
    }

    #Wait for all parallel commands to finish before you finish and close the threadpool
    threads.join()
    threads.close()
  end

  # Function that stops the peers of the network in a polite manner. First the bootstrap is stopped so that
  # it gets that global statistics form all the peers. Then, the rest of the peers are stopped in parallel.
  def stop_peers()
    logger.info("[Stopping Peers]")

    mutex = Mutex.new
    percentage =  0.0
    threads = ThreadPool.new(20)

    #First stop the bootstrap giving it the chance to collect global statistics from all the other peers
    logger.info("[ #{Integer(100*(percentage/peers.size))}% ][Stopping Peers] Killing Bootstrap: #{peers[0]}")
    execute "java -cp #{@classpath} fr.inria.gemo.vip2p.node.controler.ControlModule SHUTDOWN_REMOTE #{peers[0].hostname} #{peers[0].rmi_port} 0",true
    mutex.synchronize {percentage += 1}
    logger.info("[ #{Integer(100*(percentage/peers.size))}% ][Stopping Peers] #{peers[0]} Bootstrap Killed")

    sleep(5)


    #Then stop all other peers in parallel
    peers[1..peers.size].each do |peer|
      threads.execute {
        logger.info("[ #{Integer(100*(percentage/peers.size))}% ][Stopping Peers] Killing #{peer}")
        execute "java -cp #{@classpath} fr.inria.gemo.vip2p.node.controler.ControlModule SHUTDOWN_REMOTE #{peer.hostname} #{peer.rmi_port} 0",true
        mutex.synchronize {percentage += 1}
        logger.info("[ #{Integer(100*(percentage/peers.size))}% ][Stopping Peers] #{peer} Killed")
      }
    end
    threads.join()
    threads.close()
  end

  # Function that executes a given command to all the physical hosts
  def remote_execute(command, concurrency = 100, strict_checking=true)
    logger.info("[Remote Command Execution]: " + "\"" + command + "\"")

    mutex = Mutex.new
    percentage =  0.0
    threads = ThreadPool.new(concurrency)

    @physical_hosts.each do |hostname, peers|
      threads.execute {
        logger.info("[ #{Integer(100*(percentage/@physical_hosts.size))}% ][Remote Command Execution] Executing in #{hostname}")
        execute(ssh(hostname) + "\'. ~/.profile; #{command}\'", true, strict_checking)
        mutex.synchronize {percentage += 1}
        logger.info("[ #{Integer(100*(percentage/@physical_hosts.size))}% ][Remote Command Execution] #{hostname} finished")
      }
    end

    threads.join()
    threads.close()
  end

  # Function that retrieves all the log files/statistics from all the peers in the network.
  def get_logs()
    mutex = Mutex.new
    percentage = 0.0
    logger.info("[Getting Logs]")
    logger.info("[Getting Logs] Started")
    threads = ThreadPool.new(100)
    path_to_logs = "#{remote_root}logs/"

    @log_repo += "/#{Time.now.strftime("%d-%m-%y")}/#{Time.now.strftime("%H.%M")}/"
    @log_repo.gsub!("//","/")
    @physical_hosts.each do |host, peers|
      log_store = "#{@log_repo}/#{host}/"
      FileUtils.mkdir_p(log_store)

      threads.execute {
        logger.info("[ #{Integer(100*(percentage/@physical_hosts.size))}% ][Getting Logs] Getting logs from #{host}...")

        execute(rsync() + "#{host}:#{path_to_logs}* #{log_store}")
        mutex.synchronize {percentage += 1}

        logger.info("[ #{Integer(100*(percentage/@physical_hosts.size))}% ][Getting Logs] #{host} finished.")
      }
    end

    threads.join()
    threads.close()

    logger.info("[Getting Logs] Finished. Logs were stored in: #{@log_repo}")
    @logger.close()
    FileUtils.cp([@deployer_log], @log_repo)
    FileUtils.rm([@deployer_log])
  end

  # Function that starts all peers in the network
  def start_peers()
    logger.info "[Starting Peers...]"
    threads = ThreadPool.new(peers.size)
    
    # Start all the peers redirecting their output to a log file
    peers.each do |peer|
      threads.execute {
        vip2p_start_command = "java -Xms#{config['Xms']}m -Xmx#{config['Xmx']}m #{config['acceptDebugConnection']=="yes" ? "-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=#{peer.port + 200}" : "" } -cp #{@classpath}#{@jar_mode? ":" + @jar_file : ""} fr.inria.gemo.vip2p.node.controler.ControlModule STARTUP #{peers[0].hostname} #{peers[0].port} #{peers[0].rmi_port} #{peer.hostname} #{peer.port} #{peer.rmi_port} ."
        command = ssh(peer.hostname) + "\'. ~/.profile 2>/dev/null;cd #{@remote_root}; #{vip2p_start_command} \'"
        logger.debug("Executing: #{command}")
        execute(command,true)
      }
    end

    threads.join()
    threads.close()
    
    end
  
  # Main function that is called when the deployer is started
  def run()
    if @stop_mode
      stop_peers()
      if @get_logs_mode
        get_logs()
      end
      exit(0)
    end

    if @kill_mode
      logger.info("[Killing Peers...]")
      remote_execute('kill -9 `ps -eo pid,args | grep ControlModule | grep -v grep | cut -c1-6`', 100, false)
      exit(0)
    end

    if @get_logs_mode
      get_logs()
      exit(0)
    end

    if @remote_execution_mode
      remote_execute(@remote_execution_command)
      exit(0)
    end

    display_overview()

    distribute_data()

    if not @jar_mode
      logger.info("[Compiling Code...]")
      remote_execute(". ~/.profile 2>/dev/null;cd #{@remote_root}; make debugCompile=-g > /dev/null")
    end

    if config['generateData']=="true"
      eval("#{config['generateData.functioncall']}")
    end
    
    start_peers()

  end

end




################################################################################
# Helper Classes used by the deployer
# No need to touch them
################################################################################
require "thread"

class ThreadPool
  
  class Executor
    attr_reader :active
    
    def initialize(queue, mutex)
      @thread = Thread.new do
        loop do
          mutex.synchronize { @tuple = queue.shift }
          if @tuple
            args, block = @tuple
            @active = true
            begin
              block.call(*args)
            rescue Exception => e
              STDERR.puts e.message
              STDERR.puts e.backtrace.join("\n")
              exit 1
            end
            block.complete = true
          else
            @active = false
            sleep 0.05
          end
        end
      end
    end
    
    def close
      @thread.exit
    end
  end
  
  attr_accessor :queue_limit
  
  # Initialize with number of threads to run
  def initialize(count, queue_limit = 0)
    @mutex = Mutex.new
    @executors = []
    @queue = []
    @queue_limit = queue_limit
    @count = count    
    count.times { @executors << Executor.new(@queue, @mutex) }

  end
  
  # Runs the block at some time in the near future
  def execute(*args, &block)
    init_completable(block)
    
    if @queue_limit > 0
      sleep 0.01 until @queue.size < @queue_limit
    end
      
    @mutex.synchronize do
      @queue << [args, block]
    end
  end
  
  # Runs the block at some time in the near future, and blocks until complete  
  def synchronous_execute(*args, &block)
    execute(*args, &block)
    sleep 0.01 until block.complete?
  end
  
  # Size of the task queue
  def waiting
    @queue.size
  end
    
  # Size of the thread pool
  def size
    @count
  end
  
  # Kills all threads
  def close
    @executors.each {|e| e.close }
  end
  
  # Sleeps and blocks until the task queue is finished executing
  def join
    sleep 0.01 until @queue.empty? and @executors.all?{|e| !e.active}
  end
  
protected
  def init_completable(block)
    block.extend(Completable)
    block.complete = false
  end
  
  module Completable
    def complete=(val)
      @complete = val
    end
    
    def complete?
      !!@complete
    end
  end
end

class Open4
  def Open4.popen4(*cmd)
    pw = IO::pipe   # pipe[0] for read, pipe[1] for write
    pr = IO::pipe
    pe = IO::pipe

    verbose = $VERBOSE
    begin
      $VERBOSE = nil
      
      cid =
        fork{
          # child
          pw[1].close
          STDIN.reopen(pw[0])
          pw[0].close

          pr[0].close
          STDOUT.reopen(pr[1])
          pr[1].close

          pe[0].close
          STDERR.reopen(pe[1])
          pe[1].close

          STDOUT.sync = true
          STDERR.sync = true

          exec(*cmd)
        }
    ensure
      $VERBOSE = verbose
    end

    pw[0].close
    pr[1].close
    pe[1].close
    pi = [pw[1], pr[0], pe[0]]
    pw[1].sync = true
    if defined? yield
      begin
        yield(cid, *pi)
        return(Process::waitpid2(cid).last)
      ensure
        pi.each{|p| p.close unless p.closed?}
      end
    end
    [cid, pw[1], pr[0], pe[0]]
  end
  
end

#hack the format of the default logger and write the messages to stdout
class Logger
  class Formatter    
    #keep the original signature but alter implementation to change formatting
    def call(severity, time, progname, msg)
      puts str = "[%s] [%-5s]: %s\n" % [format_datetime(time),severity, msg2str(msg)]
      return str
    end
  end

  # hack the logger to output messages also from the << method
  def <<(msg)
    puts msg
    @logdev.write(msg)
  end
end
##############################################################################
# End of helper Classes
##############################################################################


# Main Function
# Create a new deployer instance and run it.
deployer = Deployer.new
deployer.run()

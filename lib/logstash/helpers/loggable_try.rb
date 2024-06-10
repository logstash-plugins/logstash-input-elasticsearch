require 'stud/try'

module LogStash module Helpers
  class LoggableTry < Stud::Try
    def initialize(logger, name)
      @logger = logger
      @name = name
    end

    def log_failure(exception, fail_count, message)
      @logger.warn("Attempt to #{@name} but failed. #{message}", fail_count: fail_count, exception: exception.message)
    end
  end
end end
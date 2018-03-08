require 'thread'
require '../Fpnn.rb'

$lock = Mutex.new
$seq = 0

$client = Fpnn::Client.new("localhost", 13099)
$client.enableEncryptor(File.read('../server-public.pem'))

def getSeq()
	$lock.synchronize {
        $seq += 1
        return $seq
	}
end

class MyCallback < Fpnn::FpnnCallback
	@seqNum	

	def initialize(seqNum)
		@seqNum = seqNum
	end

    def callback(answer, exception)
        if exception == nil
        	readSeqNum = answer['seqNum']
			if readSeqNum != @seqNum
                p "exception: seqnum wrong"
			end
		else
            p exception
        end
    end
end

def asyncTest()
    while (true)
        seqNum = getSeq()
        $client.sendQuest("test", {"seqNum" => seqNum}, MyCallback.new(seqNum))
		sleep(Random.new.rand)
    end
end

def syncTest()
    while (true)
        seqNum = getSeq()
        begin
            answer = $client.sendQuestSync("test", {"seqNum" => seqNum})
            readSeqNum = answer['seqNum']
            if readSeqNum != seqNum
                p "exception: seqnum wrong"
            end
        rescue StandardError => e
            p e 
		end
		sleep(Random.new.rand)
    end
end

threads = []
for i in 0..20
	threads << Thread.new{ asyncTest() }
end

for i in 0..20
	threads << Thread.new{ syncTest() }
end

while (true)
	sleep(1)
end


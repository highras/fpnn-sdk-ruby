require 'msgpack'
require 'date'
require 'socket'
require 'openssl'
require 'base64'
require 'digest'
require 'thread'
include OpenSSL

module Fpnn
	
    FPNN_RUBY_VERSION = 1
    FPNN_FLAG_MSGPACK = 0x80
    FPNN_MT_ONEWAY = 0
    FPNN_MT_TWOWAY = 1
    FPNN_MT_ANSWER = 2

    class FpnnCallback
        attr_accessor :timeoutSecond
        attr_accessor :createTime
		attr_accessor :syncMutex
        attr_accessor :syncSemaphore
        attr_accessor :syncAnswer
        attr_accessor :syncException

        def initialize()
            @timeoutSecond = 0
            @createTime = 0
			@syncMutex = nil
            @syncSemaphore = nil
            @syncAnswer = nil
            @syncException = nil
        end

        def callback(answer, exception)
        end
    end

    class Header
        attr_accessor :magic
        attr_accessor :version
    	attr_accessor :flag
    	attr_accessor :mtype
    	attr_accessor :ss
        attr_accessor :psize

        def initialize(magic, version, flag, mtype, ss, psize)
            @magic = magic
            @version = version
            @flag = flag
            @mtype = mtype
            @ss = ss
            @psize = psize
        end

        def packHeader()
            return [@magic, @version, @flag, @mtype, @ss, @psize].pack("A*CCCCV")
        end
    end

    class Quest
        attr_accessor :header
        attr_accessor :cTime
        attr_accessor :seqNum
        attr_accessor :payload
        attr_accessor :method
        $nextSeq

        def initialize(method, params, oneway = false)
            @header = Header.new("FPNN", FPNN_RUBY_VERSION, 0, 0, 0, 0)
            @header.mtype = oneway ? FPNN_MT_ONEWAY : FPNN_MT_TWOWAY
            @header.ss = method.length
            if not $oneway
                 @seqNum = self.nextSeqNum()
            end
            @method = method
            @payload = ""
            @header.flag = FPNN_FLAG_MSGPACK
            @payload = params.to_msgpack
            @header.psize = @payload.length
            @cTime = DateTime.now.strftime('%Q')
        end

        def nextSeqNum()
            if $nextSeq == nil
                $nextSeq = 0
            end
            if $nextSeq >= 2147483647
                $nextSeq = 0	
            end
            $nextSeq += 1
            return $nextSeq 
        end

        def raw()
            packet = @header.packHeader()
            if @header.mtype == FPNN_MT_TWOWAY
                packet << [@seqNum].pack("V")
            end
            packet << [@method, @payload].pack("A*A*")
            return packet
        end
    end

    class Client
        
        @socket
        @ip
        @port
        @timeout
        @iv
        @key
        @strength
        @isEncryptor
        @canEncryptor
        @semaphore
        @rThread
        @cbDict
        @dictLock
        @stop
		@cThreaad

        def initialize(ip, port, timeout = 5)
            @ip = ip
            @port = port
            @stop = false
            @timeout = timeout
            @socket = nil
            @semaphore = Mutex.new
            @rThread = nil
            @cbDict = {}
            @dictLock = Mutex.new
			self.startCheckTimeoutThread()
        end

        def reconnect()
            @semaphore.synchronize {
                @socket = TCPSocket.new(@ip, @port)
            }
            self.startReceiveThread()
        end

        def connect()
            self.reconnect()  
        end

		def startCheckTimeoutThread()
            if @cThread == nil
                @cThread = Thread.new{ self.timeoutChecker() }
            end
        end

		def timeoutChecker()
			while (not @stop)
				sleep(1)
				timeoutList = []
				@dictLock.synchronize {
					@cbDict.each { |seqNum, cb|
						if self.isCallbackTimeout(cb)
							timeoutList << seqNum
						end
					}
				}
				timeoutList.each{ |seqNum|
					cb = self.getCb(seqNum)
					if cb != nil
						self.invokeCallback(cb, nil, StandardError.new("Quest timeout"))
					end
				}
			end
		end

		def isCallbackTimeout(cb)
			timeoutValue = @timeout
			if cb.timeoutSecond > 0
				timeoutValue = cb.timeoutSecond
			end
			if timeoutValue > 0
				now = Time.now.to_i
				return now - cb.createTime >= timeoutValue
			end
			return false 
		end

        def close()
          	@stop = true
			@semaphore.synchronize {
				@socket.close()
			}
			if @rThread != nil 
				@rThread.join()
				@rThread = nil 
			end
			if @cThread != nil
				@cThread.jion()
			end
        end

        def putCb(seqNum, cb)
            @dictLock.synchronize {
                @cbDict[seqNum] = cb
            }
        end

        def getCb(seqNum)
            cb = nil
            @dictLock.synchronize {
                cb = @cbDict.fetch(seqNum, nil)
                @cbDict.delete(seqNum)
            }
            return cb
        end

        def startReceiveThread()
            if @rThread == nil
                @rThread = Thread.new{ self.receiveThread() }
            end
        end

        def enableEncryptor(peerPubData, curveName = 'secp256k1', strength = 128)
            if not ['secp256k1', 'secp256r1', 'secp192r1', 'secp224r1'].include?(curveName)
                curveName = 'secp256k1'
            end
            if not [128, 256].include?(strength)
                strength = 128
            end
            @strength = strength
            peerPubKey = OpenSSL::PKey::EC.new(peerPubData)

            ec = OpenSSL::PKey::EC.new(curveName)
            ec.generate_key

            pubKey = ec.public_key.to_bn.to_s(2)[1..-1]
           
            secret = ec.dh_compute_key(peerPubKey.public_key)
            
            @iv = Digest::MD5.digest(secret)

            if strength == 128
                @key = secret[0..15]
            else
                if secret.length == 32
                    @key = secret
                else
                    @key = Digest::SHA256.digest(secret)
                end
            end

            @isEncryptor = true
            @canEncryptor = false
            self.sendQuest("*key", {"publicKey" => pubKey, "streamMode" => false, "bits" => @strength})
        end

        def sendAll(buffer)
            len = buffer.length
            @semaphore.synchronize {
                while (len > 0)
                    sendBytes = @socket.send(buffer, 0)
                    if sendBytes < len 
                        buffer = buffer[sendBytes..-1] 
                    end
                    len -= sendBytes
                end
            }
        end

        def readAll(len)
            data = ""
			while (tmp = @socket.recv(len))
				data += tmp
				break if data.length >= len 
			end
            return data
        end

        def receiveThread()
            while (not @stop)
				begin
                    arr = []
                    if (@isEncryptor)
                        buffer = readAll(4)
                        arr = buffer.unpack("V")
                        buffer = readAll(arr[0])
                        buffer = self.encrypt(buffer, false) 
                        arr = buffer.unpack("A4CCCCVVA*")
                    else
                        buffer = readAll(16)
                        arr = buffer.unpack("A4CCCCVV")
                    end
                    
					seqNum = arr[6]
                    payload = ''
                    if @isEncryptor
                        payload = arr[7]
                    else
                        payload = self.readAll(arr[5])
                    end
                    
                    answer = MessagePack.unpack(payload)
                    
					cb = self.getCb(seqNum)
	
					self.invokeCallback(cb, answer, nil)

				rescue EOFError => e
                rescue StandardError => e
                	begin
						if @stop
							break
						end
						self.reconnect()
					rescue
						break
					end
				end

            end

			self.exceptionFlushAll()
			@rThread = nil
        end

        def encrypt(buffer, isEncrypt)
            strength = "128-CFB"
            if @strength == 256
                strength = "256-CFB"
            end
            ret = ''
            cipher = OpenSSL::Cipher::AES.new(strength)
            cipher.key = @key
            cipher.iv = @iv
            if isEncrypt 
                cipher.encrypt 
                ret = cipher.update(buffer) + cipher.final
            else
                cipher.decrypt
                ret = cipher.update(buffer) + cipher.final
            end
            return ret
        end

        def sendQuest(method, params, cb = nil, timeout = 0)
            if cb != nil
				cb.syncMutex = nil
            	cb.syncSemaphore = nil
				cb.syncAnswer = nil
				cb.syncException = nil 
				cb.timeoutSecond = timeout
				cb.createTime = Time.now.to_i
			end
            self.send(method, params, cb)
        end

        def sendQuestSync(method, params, timeout = 0)
            cb = FpnnCallback.new
			cb.syncMutex = Mutex.new
			cb.syncSemaphore = ConditionVariable.new 
			cb.syncAnswer = nil
			cb.syncException = nil
			cb.timeoutSecond = timeout
			cb.createTime = Time.now.to_i 
			self.send(method, params, cb)

			cb.syncMutex.synchronize {
				cb.syncSemaphore.wait(cb.syncMutex)
			}

			if cb.syncException == nil
				return cb.syncAnswer
			else
				raise cb.syncException
			end
        end

        def send(method, params, cb = nil)
            begin
                oneway = (method != "*key" and cb == nil)
                
                quest = Quest.new(method, params, oneway)
                
                if @socket == nil
                    self.reconnect()
                end

                buffer = quest.raw()

                if @isEncryptor && method != "*key"
                    buffer = [buffer.length, self.encrypt(buffer, true)].pack("VA*")
                end
                
				self.sendAll(buffer)
                
                @canEncryptor = false
                
				if oneway or cb == nil
                    return 
                end

				self.putCb(quest.seqNum, cb)
	
            rescue StandardError => e
            	self.invokeCallback(cb, nil, e)
			end
        end

        def invokeCallback(cb, answer, exception)
           	if cb != nil
				if cb.syncSemaphore == nil
					cb.callback(answer, exception)
				else
					cb.syncAnswer = answer
					cb.syncException = exception
					cb.syncMutex.synchronize {
						cb.syncSemaphore.signal
					}
				end
			end
        end

		def exceptionFlushAll()
			@dictLock.synchronize {
				removeList = []	
				@cbDict.each { |seqNum, cb|
					removeList << seqNum
					self.invokeCallback(cb, None, Exception("connection was broken"))
				}
				removeList.each { |seqNum|
					@cbDict.delete(seqNum)
				}
			}
		end
    end

end

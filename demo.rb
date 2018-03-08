require './Fpnn.rb'

client = Fpnn::Client.new("localhost", 13099)

client.enableEncryptor(File.read('./server-public.pem'))

class MyCallback < Fpnn::FpnnCallback
    def callback(answer, exception)
        if exception == nil
            p "answer:"
            p answer
        else
            p "exception:"
            p exception
        end
    end
end

while true
    client.sendQuest("two", {"aa"=>1, "bb"=>"str"}, MyCallback.new)

    begin
        answer = client.sendQuestSync("two", {"aa"=>1, "bb"=>"str"})
        p "sync answer:"
        p answer
    rescue StandardError => e
        p "sync exception:"
        p e
    end
    sleep 1
end

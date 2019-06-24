using System;
using System.IO;
using TLSchema;
using TLSharp.MTProto;
using TLSharp.MTProto.Crypto;

namespace TLSharp
{
    public class Session
    {
	    private const string defaultConnectionAddress = "149.154.175.100";//"149.154.167.50";

		private const int defaultConnectionPort = 443;

        internal DataCenter DataCenter { get; set; }
        public AuthKey AuthKey { get; set; }
        public ulong Id { get; set; }
        public int Sequence { get; set; }
        public ulong Salt { get; set; }
        public int TimeOffset { get; set; }
        public long LastMessageId { get; set; }
        public int SessionExpires { get; set; }
        public TLUser TLUser { get; set; }
        private static Random random = new Random();

        internal Session(ulong id, AuthKey authKey, int sequence, ulong salt, int timeOffset, long lastMessageId, int expires, TLUser user, DataCenter dc)
        {
            this.Id = id;
            AuthKey = authKey;
            Sequence = sequence;
            Salt = salt;
            TimeOffset = timeOffset;
            LastMessageId = lastMessageId;
            SessionExpires = expires;
            TLUser = user;
            DataCenter = dc;
        }

        private Session()
        {
        }

        internal Session Clone()
        {
            return FromBytes(ToBytes());
        }

        public byte[] ToBytes()
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write(Id);
                writer.Write(Sequence);
                writer.Write(Salt);
                writer.Write(LastMessageId);
                writer.Write(TimeOffset);
                Serializers.String.write(writer, DataCenter.Address);
                writer.Write(DataCenter.Port);

                if (TLUser != null)
                {
                    writer.Write(1);
                    writer.Write(SessionExpires);
                    ObjectUtils.SerializeObject(TLUser, writer);
                }
                else
                {
                    writer.Write(0);
                }

                Serializers.Bytes.write(writer, AuthKey.Data);

                return stream.ToArray();
            }
        }

        public static Session FromBytes(byte[] buffer)
        {
            using var stream = new MemoryStream(buffer);
            return FromStream(stream);
        }

        public static Session FromStream(Stream stream)
        {
            using (var reader = new BinaryReader(stream))
            {
                var id = reader.ReadUInt64();
                var sequence = reader.ReadInt32();
                var salt = reader.ReadUInt64();
                var lastMessageId = reader.ReadInt64();
                var timeOffset = reader.ReadInt32();
                var serverAddress = Serializers.String.read(reader);
                var port = reader.ReadInt32();

                var isAuthExsist = reader.ReadInt32() == 1;
                int sessionExpires = 0;
                TLUser TLUser = null;
                if (isAuthExsist)
                {
                    sessionExpires = reader.ReadInt32();
                    TLUser = (TLUser)ObjectUtils.DeserializeObject(reader);
                }

                var authData = Serializers.Bytes.read(reader);
                var defaultDataCenter = new DataCenter(serverAddress, port);

                return new Session(id, new AuthKey(authData), sequence, salt, timeOffset, lastMessageId, sessionExpires, TLUser, defaultDataCenter);
            }
        }

        public static Session New()
        {
            var defaultDataCenter = new DataCenter (defaultConnectionAddress, defaultConnectionPort);

            return new Session()
            {
                Id = GenerateRandomUlong(),
                DataCenter = defaultDataCenter,
            };
        }

        private static ulong GenerateRandomUlong()
        {
            var random = new Random();
            ulong rand = (((ulong)random.Next()) << 32) | ((ulong)random.Next());
            return rand;
        }

        public long GetNewMessageId()
        {
            long time = Convert.ToInt64((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds);
            long newMessageId = ((time / 1000 + TimeOffset) << 32) |
                                ((time % 1000) << 22) |
                                (random.Next(524288) << 2); // 2^19
                                                            // [ unix timestamp : 32 bit] [ milliseconds : 10 bit ] [ buffer space : 1 bit ] [ random : 19 bit ] [ msg_id type : 2 bit ] = [ msg_id : 64 bit ]

            if (LastMessageId >= newMessageId)
            {
                newMessageId = LastMessageId + 4;
            }

            LastMessageId = newMessageId;
            return newMessageId;
        }
    }
}

namespace CLIENT.Models
{
    public class Match
    {
        public string League { get; set; }
        public string HomeTeam { get; set; }
        public string AwayTeam { get; set; }
        public int? HomeScore { get; set; }
        public int? AwayScore { get; set; }
        public string Status { get; set; }
    }

    public class FootballDashboardModel
    {
        public List<Match> LiveMatches { get; set; } = new List<Match>();
        public List<Match> TodayMatches { get; set; } = new List<Match>();
    }
}

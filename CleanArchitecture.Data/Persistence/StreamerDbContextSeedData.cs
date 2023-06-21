using CleanArchitecture.Domain;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace CleanArchitecture.Infrastructure.Persistence
{
    public class StreamerDbContextSeedData
    {
        public static async Task LoadDataAsync(StreamerDbContext context, ILoggerFactory loggerFactory)
        {
            try
            {
                var videos = new List<Video>();
                if(!context.Directores!.Any())
                {
                    var directorData = File.ReadAllText("../CleanArchitecture.Data/Data/director.json");
                    var directores = JsonSerializer.Deserialize<List<Director>>(directorData);
                    await context.Directores!.AddRangeAsync(directores!);
                    await context.SaveChangesAsync();
                }

                if (!context.Videos!.Any())
                {
                    var videoData = File.ReadAllText("../CleanArchitecture.Data/Data/video.json");
                    videos = JsonSerializer.Deserialize<List<Video>>(videoData);
                    await GetPreConfiguredVideoDirectorAsync(videos!, context);
                    //await context.Videos!.AddRangeAsync(videos!);
                    await context.SaveChangesAsync();
                }

                if (!context.Actores!.Any())
                {
                    var actorData = File.ReadAllText("../CleanArchitecture.Data/Data/actor.json");
                    var actores = JsonSerializer.Deserialize<List<Actor>>(actorData);
                    await context.Actores!.AddRangeAsync(actores!);

                    await context.AddRangeAsync(GetPreConfiguredVideoActor(videos!));
                    await context.SaveChangesAsync();
                }

            }
            catch(Exception ex)
            {
                var logger = loggerFactory.CreateLogger<StreamerDbContextSeedData>();
                logger.LogError(ex.Message);
            }
        }

        private static async Task GetPreConfiguredVideoDirectorAsync(List<Video> videos, StreamerDbContext context)
        {
            var random = new Random();
            foreach(var video in videos)
            {
                video.DirectorId = random.Next(1, 99);
            }
            await context.Videos!.AddRangeAsync(videos);
        }

        private static IEnumerable<VideoActor> GetPreConfiguredVideoActor(List<Video> videos)
        {
            var videoActors = new List<VideoActor>();
            var random = new Random();

            foreach(var video in videos)
            {
                var videoActor = new VideoActor
                {
                    VideoId = video.Id,
                    ActorId = random.Next(1, 99)
                };
                videoActors.Add(videoActor);
            }

            return videoActors;
        }
    }
}

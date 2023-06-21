namespace CleanArchitecture.Application.Specifications.Videos
{
    public class VideoSpecificationParams: SpecificationParams
    {
        public int? StreamerId { get; set; }
        public int? DirectorId { get; set; }
    }
}

using auth_service.Models.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

public class ApplicationDbContext : DbContext
{
    private readonly ILogger<ApplicationDbContext> _logger;

    public ApplicationDbContext(
        DbContextOptions<ApplicationDbContext> options,
        ILogger<ApplicationDbContext> logger) : base(options)
    {
        _logger = logger;
    }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfiguration(new UserConfiguration());
    }

    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await base.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving changes to database");
            throw;
        }
    }
}

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(user => user.Id);
        builder.Property(user => user.Email)
            .IsRequired()
            .HasMaxLength(100);
        builder.HasIndex(user => user.Email)
            .IsUnique();
        builder.Property(user => user.Username)
            .IsRequired()
            .HasMaxLength(50);
        builder.Property(user => user.PasswordHash)
            .IsRequired();
        builder.Property(user => user.CreatedAt)
            .HasColumnType("timestamp")
            .HasDefaultValueSql("CURRENT_TIMESTAMP")
            .ValueGeneratedOnAdd();
        builder.Property(user => user.UpdatedAt)
            .HasColumnType("timestamp")
            .HasDefaultValueSql("CURRENT_TIMESTAMP")
            .ValueGeneratedOnAddOrUpdate();
        builder.Property(user => user.LastLoginAt)
            .HasColumnType("timestamp")
            .IsRequired(false);
    }
}
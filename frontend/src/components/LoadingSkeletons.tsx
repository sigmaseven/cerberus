import { Skeleton, TableRow, TableCell, Box } from '@mui/material';

interface TableSkeletonProps {
  rows?: number;
  columns?: number;
}

/**
 * Loading skeleton for table rows
 * Provides better UX during data loading by showing placeholder content
 */
export function TableSkeleton({ rows = 10, columns = 5 }: TableSkeletonProps) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <TableRow key={i}>
          {Array.from({ length: columns }).map((_, j) => (
            <TableCell key={j}>
              <Skeleton variant="text" width="100%" animation="wave" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}

interface CardSkeletonProps {
  count?: number;
}

/**
 * Loading skeleton for cards
 */
export function CardSkeleton({ count = 3 }: CardSkeletonProps) {
  return (
    <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
      {Array.from({ length: count }).map((_, i) => (
        <Box key={i} sx={{ flex: '1 1 300px', minWidth: 300 }}>
          <Skeleton variant="rectangular" height={200} animation="wave" />
          <Box sx={{ pt: 1 }}>
            <Skeleton animation="wave" />
            <Skeleton width="60%" animation="wave" />
          </Box>
        </Box>
      ))}
    </Box>
  );
}

/**
 * Loading skeleton for dashboard stats
 */
export function DashboardStatsSkeleton() {
  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 2 }}>
      {Array.from({ length: 4 }).map((_, i) => (
        <Box key={i}>
          <Skeleton variant="rectangular" height={120} animation="wave" />
        </Box>
      ))}
    </Box>
  );
}

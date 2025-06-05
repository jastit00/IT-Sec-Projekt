export const defaultChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom',
      align: 'center',
      labels: {
        boxWidth: 25,
        padding: 15,
        font: {
          size: 20
        }
      }
    },
    tooltip: {
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      padding: 10,
      titleFont: {
        size: 14
      },
      bodyFont: {
        size: 13
      }
    }
  }
};